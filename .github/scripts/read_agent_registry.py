"""Fixed candidate registry reconciliation. Never transfers or modifies images."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from publish_agent_oci import (ACCOUNT_SHA256, CONFIG, MANIFEST, REPO, REVISION, RUN,
                               command, digest_matches, download, private_json, verify_local)

WORKFLOW = 'Read qualified agent registry (pull only)'


def context(env):
    if any(env.get(k) != v for k, v in {
        'GITHUB_REPOSITORY': REPO, 'GITHUB_REF': 'refs/heads/main',
        'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
        'GITHUB_WORKFLOW': WORKFLOW}.items()):
        raise ValueError('Manual main-only context required')


def readback(root, env, execute=command, verify=verify_local):
    verify(root)
    account, token = env.get('CLOUDFLARE_ACCOUNT_ID', ''), env.get('CLOUDFLARE_API_TOKEN', '')
    if (not re.fullmatch('[a-f0-9]{32}', account)
            or hashlib.sha256(account.encode()).hexdigest() != ACCOUNT_SHA256
            or not re.fullmatch('[A-Za-z0-9_-]{20,256}', token)):
        raise ValueError('Existing account authorization refused')
    runtime = Path(env['RUNNER_TEMP'])
    private_json(runtime / 'exp710-readback-attempt.json', {'sourceRun': RUN})
    report = {'version': 1, 'result': 'unverified', 'sourceRun': RUN, 'revision': REVISION,
              'manifestDigest': MANIFEST, 'configDigest': CONFIG, 'accountSha256': ACCOUNT_SHA256,
              'stage': 'tools', 'authAttempted': False, 'copyPerformed': False, 'retryPerformed': False}
    private = None
    try:
        wrangler = Path(__file__).resolve().parents[2] / 'deploy/cloudflare/node_modules/wrangler'
        if json.loads((wrangler / 'package.json').read_text())['version'] != '4.158.0':
            raise ValueError('Pinned Wrangler required')
        with tempfile.TemporaryDirectory(prefix='exp710-readback-auth-', dir=runtime) as temporary:
            private = Path(temporary)
            safe = {'PATH': env['PATH'], 'HOME': temporary, 'TMPDIR': temporary,
                    'XDG_RUNTIME_DIR': temporary, 'CI': 'true'}
            version = execute(['skopeo', '--version'], env=safe, cwd=private).decode().strip()
            if len(version) > 128 or not version.startswith('skopeo version '):
                raise ValueError('Inspection tool refused')
            help_text = execute(['skopeo', 'inspect', '--help'], env=safe, cwd=private).decode()
            if not all(flag in help_text for flag in ['--raw', '--config', '--authfile', '--retry-times']):
                raise ValueError('Inspection capability missing')
            report.update(stage='auth', authAttempted=True)
            auth_env = dict(safe, CLOUDFLARE_ACCOUNT_ID=account, CLOUDFLARE_API_TOKEN=token,
                            WRANGLER_LOG='error', WRANGLER_SEND_METRICS='false')
            credentials = json.loads(execute(['node', str(wrangler / 'bin/wrangler.js'), 'containers',
                'registries', 'credentials', 'registry.cloudflare.com', '--pull',
                '--expiration-minutes', '15', '--json'], env=auth_env, cwd=private))
            password = credentials.get('password', '')
            if not isinstance(password, str) or not re.fullmatch('[A-Za-z0-9._~-]{20,16384}', password):
                raise ValueError('Temporary pull authorization refused')
            authfile = private / 'auth.json'
            private_json(authfile, {'auths': {'registry.cloudflare.com': {
                'auth': base64.b64encode(('v1:' + password).encode()).decode()}}})
            destination = 'docker://registry.cloudflare.com/' + account + '/vlpds@' + MANIFEST
            for stage, flags, digest in [('manifest', ['--raw'], MANIFEST),
                                         ('config', ['--config', '--raw'], CONFIG)]:
                report['stage'] = stage
                raw = execute(['skopeo', '--command-timeout', '60s', 'inspect', *flags,
                    '--retry-times', '0', '--tls-verify=true', '--authfile', str(authfile),
                    destination], env=safe, cwd=private, timeout=70)
                if not digest_matches(raw, digest):
                    raise ValueError('Remote bytes differ')
            report.update(result='verified', stage='complete', remoteVerified=True)
    except Exception:
        # No stderr, headers, account identifier, or credential enters the receipt.
        report['result'] = 'unverified'
    report['temporaryAuthRemoved'] = private is None or not private.exists()
    if not report['temporaryAuthRemoved']:
        report.update(result='unverified', stage='cleanup')
    private_json(runtime / 'exp710-readback-receipt.json', report)
    return report


def main():
    os.umask(0o077)
    try:
        context(os.environ)
        root = Path(os.environ['RUNNER_TEMP']) / 'exp710-readback-source'
        if sys.argv[1:] == ['verify']:
            root.mkdir(mode=0o700)
            download(root)
        elif sys.argv[1:] == ['read']:
            if readback(root, os.environ)['result'] != 'verified':
                raise ValueError('Readback unverified')
        else:
            raise ValueError('Invalid operation')
    except Exception:
        print('Readback not verified; stop without retry. See sanitized receipt if available.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
