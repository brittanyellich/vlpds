"""Authenticate bounded GitHub receipts only; no provider or registry access."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import zipfile
from publish_agent_oci import github, command, private_json, REPO, ACCOUNT_SHA256, MANIFEST, CONFIG

READBACK = 45773069113
HEAD = 'ad05d5b1f7ba8f1cefe2700be51c2d4415cafe53'
ARTIFACT = 15094498037
DIGEST = 'sha256:f2670b39cdab24404e2e00c4a13475a7e9cecfade332f04cc177589246c90d4b'
CODE = ['.github/workflows/cloudflare-off-staging.yml', '.github/scripts/off_staging_evidence.py',
        '.github/scripts/publish_agent_oci.py', '.github/scripts/qualify_agent_oci.py',
        'deploy/cloudflare/package-lock.json'] + ['deploy/cloudflare/scripts/' + n for n in [
        'off-staging-plan.mjs', 'off-staging-transport.mjs', 'off-staging-journal.mjs',
        'pilot-provider.mjs', 'pilot-publish.mjs', 'pilot-update-mode.mjs',
        'prepare-deploy.mjs', 'verify-artifact.mjs', 'pilot-activation-plan.mjs']]


def code_hash(root):
    pairs = [[p, hashlib.sha256((root / p).read_bytes()).hexdigest()] for p in CODE]
    return hashlib.sha256(json.dumps(pairs, separators=(',', ':')).encode()).hexdigest()


def unpack(meta, raw, name, run):
    if (meta.get('expired') is not False or meta.get('workflow_run', {}).get('id') != run
            or not re.fullmatch('sha256:[a-f0-9]{64}', meta.get('digest', ''))
            or not 0 < meta.get('size_in_bytes', 0) <= 32768
            or len(raw) != meta['size_in_bytes']
            or 'sha256:' + hashlib.sha256(raw).hexdigest() != meta['digest']):
        raise ValueError('Artifact identity/digest refused')
    with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
        entries = bundle.infolist()
        if (len(entries) != 1 or entries[0].filename != name or entries[0].flag_bits & 1
                or not 0 < entries[0].file_size <= 16384):
            raise ValueError('Single bounded JSON required')
        return json.loads(bundle.read(entries[0]))


def check_run(run, identifier, head, path, conclusions=('success',)):
    expected = {'id': identifier, 'head_sha': head, 'run_attempt': 1,
                'event': 'workflow_dispatch', 'head_branch': 'main', 'path': path,
                'status': 'completed'}
    if any(run.get(k) != v for k, v in expected.items()) or run.get('conclusion') not in conclusions:
        raise ValueError('Exact successful manual run required')


def evidence(env, get=github, execute=command, root=None):
    check_run(get('actions/runs/' + str(READBACK)), READBACK, HEAD,
              '.github/workflows/agent-runtime-readback.yml')
    meta = get('actions/artifacts/' + str(ARTIFACT))
    if meta.get('id') != ARTIFACT or meta.get('digest') != DIGEST:
        raise ValueError('Readback artifact changed')
    raw = execute(['gh', 'api', 'repos/' + REPO + '/actions/artifacts/' + str(ARTIFACT) + '/zip'])
    receipt = unpack(meta, raw, 'exp710-readback-receipt.json', READBACK)
    if any(receipt.get(k) != v for k, v in {'result': 'verified', 'remoteVerified': True,
            'manifestDigest': MANIFEST, 'configDigest': CONFIG, 'accountSha256': ACCOUNT_SHA256,
            'sourceRun': 45748259449, 'copyPerformed': False, 'retryPerformed': False,
            'temporaryAuthRemoved': True}.items()):
        raise ValueError('Registry readback refused')
    execution_hash = code_hash(root or Path(__file__).resolve().parents[2])
    result = {'manifest': MANIFEST, 'ociConfig': CONFIG, 'accountHash': ACCOUNT_SHA256,
              'executionCodeHash': execution_hash}
    if env['OPERATION'] == 'rollback':
        source = env.get('STAGE_RUN', '')
        if not re.fullmatch('[0-9]{8,20}', source):
            raise ValueError('Exact stage run required')
        source = int(source)
        run = get('actions/runs/' + str(source))
        source_head = run.get('head_sha', '')
        if not re.fullmatch('[a-f0-9]{40}', source_head):
            raise ValueError('Stage head refused')
        check_run(run, source, source_head, '.github/workflows/cloudflare-off-staging.yml',
                  ('success', 'failure', 'cancelled', 'timed_out'))
        artifacts = get('actions/runs/' + str(source) + '/artifacts?per_page=100')
        matches = [a for a in artifacts.get('artifacts', []) if a.get('name') == 'exp710-off-staging-' + str(source)]
        if artifacts.get('total_count', 101) > 100 or len(matches) != 1:
            raise ValueError('Unique stage receipt required')
        meta = matches[0]
        raw = execute(['gh', 'api', 'repos/' + REPO + '/actions/artifacts/' + str(meta['id']) + '/zip'])
        stage = unpack(meta, raw, 'exp710-off-staging-receipt.json', source)
        if (stage.get('version') != 1 or stage.get('kind') != 'exp710-off-staging'
                or stage.get('result') not in ['failed', 'verified']
                or stage.get('operation') != 'stage' or stage.get('executionCodeHash') != execution_hash
                or stage.get('head') != source_head or stage.get('run') != str(source)
                or stage.get('manifest') != MANIFEST or stage.get('ociConfig') != CONFIG
                or type(stage.get('journal')) is not int or stage['journal'] <= 0):
            raise ValueError('Verified stage provenance required')
        result['staged'] = stage.get('transition') if stage.get('result') == 'verified' else stage.get('recovery')
        recovery = result['staged']
        if (not isinstance(recovery, dict) or recovery.get('operation') != 'stage'
                or recovery.get('digest') != MANIFEST
                or not re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', recovery.get('worker', ''))
                or not re.fullmatch('[a-f0-9]{64}', recovery.get('script', ''))
                or not re.fullmatch('[a-f0-9]{64}', recovery.get('ordinary', ''))):
            raise ValueError('Verified recovery checkpoint required')
    return result


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if (os.environ.get('GITHUB_REPOSITORY') != REPO
                or os.environ.get('GITHUB_REF') != 'refs/heads/main'
                or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'
                or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
                or os.environ.get('OPERATION') not in ['stage', 'rollback']):
            raise ValueError('Manual context required')
        private_json(Path(os.environ['RUNNER_TEMP']) / 'exp710-off-evidence.json', evidence(os.environ))
    except Exception:
        print('OFF evidence refused; no provider operation permitted.', file=sys.stderr)
        sys.exit(1)
