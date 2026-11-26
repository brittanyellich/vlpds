"""Manual, fixed-artifact registry transfer. No build or Worker APIs."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile
from qualify_agent_oci import qualify, stream_digest

REPO = 'brittanyellich/vlpds'
# Existing account from the authenticated capable-OFF artifact; never print its identifier.
ACCOUNT_SHA256 = 'b75b4505b1b8e6c4ab73fba1d8600691adb7be2cc8da2a77ee52d5e19c6e543e'
RUN = 45748259449
HEAD = '27f8010c76dc58f341ed9de8ebf4c616c7ade748'
REVISION = '703c118c66277ca42c45808a2f6cc620429c6718'
MANIFEST = 'sha256:ea8627d4e368ca3bd3eafaf8c24765fa3db00c6f0c182853c4feda6bac47a488'
CONFIG = 'sha256:0c74fc9a23efdc50ea7b92359fe806ef0702dee29275f4a92337e9188c8e873a'
ARCHIVE = '68377dc1cbcc748bd767896a65c6573a2bb0fde7f82687cfe9d65fca270ecdf9'
ARTIFACTS = (
    (15084163678, 'agent-runtime-receipt-703c118-45748259449', 534,
     'ccd232075948f4cea739a27a2a8d7425d7f82d1727ce508347062e07927604bb', 'oci-qualification.json', 8192),
    (15084043877, 'agent-runtime-oci-703c118-45748259449', 176030364,
     '9692c67b7b4da38c8d0ffee25aa3dc70370356d4176cd618a988f18fc5b996ca', 'agent-runtime.oci.tar', 536870912),
)


def command(args, *, env=None, cwd=None, timeout=120):
    result = subprocess.run(args, env=env, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=True)
    if len(result.stdout) > 262144:
        raise ValueError('Command output limit')
    return result.stdout


def github(path):
    return json.loads(command(['gh', 'api', 'repos/' + REPO + '/' + path]))


def check_source(run, artifacts):
    if any(run.get(k) != v for k, v in {'id': RUN, 'run_attempt': 1, 'head_sha': HEAD,
           'event': 'workflow_dispatch', 'path': '.github/workflows/agent-runtime-qualify.yml',
           'status': 'completed', 'conclusion': 'success'}.items()):
        raise ValueError('Source run drift')
    for artifact, (identifier, name, size, digest, _, _) in zip(artifacts, ARTIFACTS):
        if any(artifact.get(k) != v for k, v in {'id': identifier, 'name': name,
               'size_in_bytes': size, 'digest': 'sha256:' + digest, 'expired': False}.items()):
            raise ValueError('Artifact metadata drift')
        if artifact.get('workflow_run', {}).get('id') != RUN:
            raise ValueError('Artifact run mismatch')
    if len(artifacts) != 2:
        raise ValueError('Both exact artifacts required')


def unpack(root):
    for identifier, _, size, digest, member, limit in ARTIFACTS:
        archive = root / (str(identifier) + '.zip')
        if archive.is_symlink() or archive.stat().st_size != size:
            raise ValueError('Artifact size/type mismatch')
        with archive.open('rb') as source:
            if stream_digest(source) != digest:
                raise ValueError('Artifact digest mismatch')
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) != 1 or entries[0].filename != member or not 0 < entries[0].file_size <= limit:
                raise ValueError('Single bounded artifact member required')
            with bundle.open(entries[0]) as source, (root / member).open('xb') as output:
                for block in iter(lambda: source.read(1048576), b''):
                    output.write(block)
    return verify_local(root)


def verify_local(root):
    receipt_path, archive = root / 'oci-qualification.json', root / 'agent-runtime.oci.tar'
    if receipt_path.is_symlink() or archive.is_symlink() or receipt_path.stat().st_size > 8192:
        raise ValueError('Local artifact refused')
    receipt = json.loads(receipt_path.read_bytes())
    expected = {'revision': REVISION, 'runtime': 'agent-a2a', 'platform': 'linux/amd64',
                'manifestDigest': MANIFEST, 'configDigest': CONFIG, 'archiveSha256': ARCHIVE,
                'capabilityVerified': True, 'registryPublished': False}
    if any(receipt.get(k) != v for k, v in expected.items()):
        raise ValueError('Candidate receipt drift')
    if qualify(archive, receipt['localVerification']) != receipt:
        raise ValueError('OCI qualification mismatch')
    return receipt


def download(root):
    check_source(github('actions/runs/' + str(RUN)),
                 [github('actions/artifacts/' + str(a[0])) for a in ARTIFACTS])
    for identifier, _, _, _, _, _ in ARTIFACTS:
        with (root / (str(identifier) + '.zip')).open('xb') as output:
            subprocess.run(['gh', 'api', 'repos/' + REPO + '/actions/artifacts/' + str(identifier) + '/zip'],
                           stdout=output, stderr=subprocess.PIPE, timeout=180, check=True)
    return unpack(root)


def private_json(path, value):
    with path.open('x') as output:
        os.chmod(path, 0o600)
        json.dump(value, output)


def digest_matches(raw, expected):
    return any("sha256:" + hashlib.sha256(candidate).hexdigest() == expected
               for candidate in [raw, raw[:-1]] if candidate == raw or raw.endswith(b"\n"))


def publish(root, env, execute=command, verify=verify_local):
    verify(root)  # Recheck all bytes immediately before any credential request.
    account = env.get('CLOUDFLARE_ACCOUNT_ID', '')
    token = env.get('CLOUDFLARE_API_TOKEN', '')
    if (not re.fullmatch('[a-f0-9]{32}', account)
            or hashlib.sha256(account.encode()).hexdigest() != ACCOUNT_SHA256
            or not re.fullmatch('[A-Za-z0-9_-]{20,256}', token)):
        raise ValueError('Existing registry authorization required')
    runtime = Path(env['RUNNER_TEMP'])
    # Persist before temporary auth or copying. No replay even after ambiguity.
    private_json(runtime / 'exp710-publication-attempt.json', {'sourceRun': RUN, 'manifestDigest': MANIFEST})
    wrangler = Path(__file__).resolve().parents[2] / 'deploy/cloudflare/node_modules/wrangler'
    if json.loads((wrangler / 'package.json').read_text())['version'] != '4.158.0':
        raise ValueError('Pinned Wrangler required')
    destination = 'registry.cloudflare.com/' + account + '/vlpds@' + MANIFEST
    with tempfile.TemporaryDirectory(prefix='exp710-registry-auth-', dir=runtime) as temporary:
        private = Path(temporary)
        safe_env = {'PATH': env['PATH'], 'HOME': temporary, 'TMPDIR': temporary,
                    'XDG_RUNTIME_DIR': temporary, 'CI': 'true'}
        tool_version = execute(['skopeo', '--version'], env=safe_env, cwd=private).decode().strip()
        if len(tool_version)>128 or not tool_version.startswith('skopeo version '):
            raise ValueError('Transfer tool refused')
        for operation, flags in [('copy', ['--preserve-digests', '--dest-authfile', '--retry-times']),
                                 ('inspect', ['--raw', '--config', '--authfile', '--retry-times'])]:
            help_text = execute(['skopeo', operation, '--help'], env=safe_env, cwd=private).decode()
            if not all(flag in help_text for flag in flags):
                raise ValueError('Transfer capability missing')
        auth_env = dict(safe_env, CLOUDFLARE_ACCOUNT_ID=account, CLOUDFLARE_API_TOKEN=token,
                        WRANGLER_SEND_METRICS='false', WRANGLER_LOG='error')
        private_json(runtime / 'exp710-registry-auth-attempt.json', {'expirationMinutes': 15})
        credentials = json.loads(execute(['node', str(wrangler / 'bin/wrangler.js'), 'containers',
                 'registries', 'credentials', 'registry.cloudflare.com', '--push', '--pull',
                 '--expiration-minutes', '15', '--json'], env=auth_env, cwd=private))
        password = credentials.get('password', '')
        if not isinstance(password, str) or not re.fullmatch('[A-Za-z0-9._~-]{20,16384}', password):
            raise ValueError('Temporary registry auth refused')
        authfile = private / 'auth.json'
        private_json(authfile, {'auths': {'registry.cloudflare.com': {
            'auth': base64.b64encode(('v1:' + password).encode()).decode()}}})
        digestfile = private / 'digest.txt'
        private_json(runtime / 'exp710-registry-copy-attempt.json', {'manifestDigest': MANIFEST})
        execute(['skopeo', '--command-timeout', '10m', 'copy', '--preserve-digests',
                 '--retry-times', '0', '--dest-tls-verify=true', '--dest-authfile', str(authfile),
                 '--digestfile', str(digestfile), 'oci-archive:' + str(root / 'agent-runtime.oci.tar'),
                 'docker://' + destination], env=safe_env, cwd=private, timeout=660)
        if digestfile.read_text().strip() != MANIFEST:
            raise ValueError('Published digest differs')
        # --config alone reserializes OCI JSON; digest verification needs raw bytes.
        for flags, expected in [(['--raw'], MANIFEST), (['--config', '--raw'], CONFIG)]:
            raw = execute(['skopeo', 'inspect', *flags, '--retry-times', '0', '--tls-verify=true',
                           '--authfile', str(authfile), 'docker://' + destination], env=safe_env, cwd=private)
            if not digest_matches(raw, expected):
                raise ValueError('Remote content differs')
    return {'version': 1, 'result': 'verified', 'sourceRun': RUN, 'revision': REVISION, 'manifestDigest': MANIFEST,
            'configDigest': CONFIG, 'archiveSha256': ARCHIVE, 'remoteVerified': True,
            'remoteImage': 'registry.cloudflare.com/<account>/vlpds@' + MANIFEST,
            'accountSha256': hashlib.sha256(account.encode()).hexdigest(),
            'workerChanges': False, 'temporaryAuthRemoved': True, 'transferTool': tool_version}


def context(env):
    if (env.get('GITHUB_REPOSITORY') != REPO or env.get('GITHUB_REF') != 'refs/heads/main'
            or env.get('GITHUB_RUN_ATTEMPT') != '1'
            or env.get('GITHUB_WORKFLOW') != 'Publish qualified agent runtime (registry only)'):
        raise ValueError('Manual main-only context required')


if __name__ == '__main__':
    os.umask(0o077)
    valid_context = False
    try:
        context(os.environ)
        valid_context = True
        root = Path(os.environ['RUNNER_TEMP']) / 'exp710-publication-source'
        if sys.argv[1:] == ['verify']:
            root.mkdir(mode=0o700)
            download(root)
        elif sys.argv[1:] == ['publish']:
            report = publish(root, os.environ)
            private_json(Path(os.environ['RUNNER_TEMP']) / 'exp710-publication-receipt.json', report)
        else:
            raise ValueError('Invalid operation')
    except Exception:
        if valid_context:
            try:
                runtime = Path(os.environ['RUNNER_TEMP'])
                private_json(runtime / 'exp710-publication-receipt.json', {
                    'version': 1, 'result': 'failed', 'sourceRun': RUN,
                    'manifestDigest': MANIFEST, 'configDigest': CONFIG,
                    'authAttempted': (runtime / 'exp710-registry-auth-attempt.json').exists(),
                    'copyAttempted': (runtime / 'exp710-registry-copy-attempt.json').exists(),
                    'retryPerformed': False, 'reconcileReadOnly': True})
            except Exception:
                pass  # Never replace an existing receipt or print a private exception.
        print('Publication-only gate failed; no retry. Reconcile registry state read-only if attempted.', file=sys.stderr)
        sys.exit(1)
