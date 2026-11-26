import hashlib
import io
import json
import unittest
from unittest.mock import patch
import zipfile
import off_staging_evidence as e


def archive(value, member):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        z.writestr(member, json.dumps(value))
    return b.getvalue()


def meta(raw, run, identifier):
    return {'id': identifier, 'expired': False, 'workflow_run': {'id': run},
            'size_in_bytes': len(raw), 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}


class EvidenceTests(unittest.TestCase):
    def fixture(self, operation='stage', partial=False):
        readback = {'result': 'verified', 'remoteVerified': True, 'manifestDigest': e.MANIFEST,
                    'configDigest': e.CONFIG, 'accountSha256': e.ACCOUNT_SHA256,
                    'sourceRun': 45748259449, 'copyPerformed': False, 'retryPerformed': False,
                    'temporaryAuthRemoved': True}
        raw = archive(readback, 'exp710-readback-receipt.json')
        metadata = meta(raw, e.READBACK, e.ARTIFACT)
        source_head = 'a' * 40
        stage_run = 45850000000
        transition = {'operation': 'stage', 'worker': '11111111-1111-1111-1111-111111111111',
                      'script': 'b' * 64, 'ordinary': 'd' * 64, 'digest': e.MANIFEST}
        stage = {'version':1,'kind':'exp710-off-staging','result': 'failed' if partial else 'verified', 'operation': 'stage',
                 'head': source_head, 'run': str(stage_run), 'manifest': e.MANIFEST,
                 'ociConfig': e.CONFIG, 'journal': 42, 'executionCodeHash': 'c' * 64,
                 'recovery' if partial else 'transition': transition}
        stage_raw = archive(stage, 'exp710-off-staging-receipt.json')
        stage_meta = meta(stage_raw, stage_run, 123)
        stage_meta['name'] = 'exp710-off-staging-' + str(stage_run)
        values = {
            'actions/runs/' + str(e.READBACK): {'id': e.READBACK, 'head_sha': e.HEAD,
                'run_attempt': 1, 'head_branch':'main', 'event': 'workflow_dispatch', 'path': '.github/workflows/agent-runtime-readback.yml',
                'status': 'completed', 'conclusion': 'success'},
            'actions/artifacts/' + str(e.ARTIFACT): metadata,
            'actions/runs/' + str(stage_run): {'id': stage_run, 'head_sha': source_head,
                'run_attempt': 1, 'head_branch':'main', 'event': 'workflow_dispatch', 'path': '.github/workflows/cloudflare-off-staging.yml',
                'status': 'completed', 'conclusion': 'failure' if partial else 'success'},
            'actions/runs/' + str(stage_run) + '/artifacts?per_page=100': {'total_count': 1, 'artifacts': [stage_meta]},
        }
        # The current main can move for unrelated work. Recovery requires the
        # exact execution-code hash and exact source-run head, not current main.
        env = {'OPERATION': operation, 'STAGE_RUN': str(stage_run), 'GITHUB_SHA': 'f' * 40}
        def execute(args):
            return stage_raw if args[-1].endswith('/123/zip') else raw
        return env, values, execute, metadata, stage

    def evaluate(self, fixture):
        env, values, execute, metadata, _ = fixture
        with patch.object(e, 'DIGEST', metadata['digest']), patch.object(e, 'code_hash', return_value='c' * 64):
            return e.evidence(env, get=values.__getitem__, execute=execute)

    def test_fixed_registry_proof(self):
        result = self.evaluate(self.fixture())
        self.assertEqual(result['manifest'], e.MANIFEST)
        self.assertNotIn('staged', result)

    def test_success_and_partial_recovery_receipts(self):
        for partial in [False, True]:
            result = self.evaluate(self.fixture('rollback', partial))
            self.assertEqual(result['staged']['worker'], '11111111-1111-1111-1111-111111111111')

    def test_source_run_attempt_or_identity_drift(self):
        for change in [{'run_attempt': 2}, {'head_branch':'untrusted'}, {'head_sha': '0' * 40}, {'event': 'push'}, {'conclusion': 'failure'}]:
            f = self.fixture()
            f[1]['actions/runs/' + str(e.READBACK)].update(change)
            with self.assertRaises(ValueError):
                self.evaluate(f)

    def test_zip_identity_hash_size_and_member(self):
        raw = archive({'safe': True}, 'receipt.json')
        m = meta(raw, 10, 1)
        for changed in [{**m, 'expired': True}, {**m, 'workflow_run': {'id': 11}},
                        {**m, 'digest': 'sha256:' + '0' * 64}, {**m, 'size_in_bytes': 32769}]:
            with self.assertRaises(ValueError):
                e.unpack(changed, raw, 'receipt.json', 10)
        with self.assertRaises(ValueError):
            e.unpack(m, raw, 'wrong.json', 10)
        self.assertEqual(e.unpack(m, raw, 'receipt.json', 10), {'safe': True})

    def test_recovery_code_or_receipt_drift(self):
        for change in [{'executionCodeHash': '0' * 64}, {'head': '0' * 40}, {'journal': None},
                       {'transition': None}, {'manifest': 'sha256:' + '0' * 64}]:
            f = self.fixture('rollback')
            f[4].update(change)
            stage_raw = archive(f[4], 'exp710-off-staging-receipt.json')
            key = 'actions/runs/' + f[0]['STAGE_RUN'] + '/artifacts?per_page=100'
            updated = meta(stage_raw, int(f[0]['STAGE_RUN']), 123)
            updated['name'] = 'exp710-off-staging-' + f[0]['STAGE_RUN']
            f[1][key]['artifacts'] = [updated]
            old_execute = f[2]
            modified = (f[0], f[1], lambda args: stage_raw if args[-1].endswith('/123/zip') else old_execute(args), f[3], f[4])
            with self.assertRaises(ValueError):
                self.evaluate(modified)


if __name__ == '__main__':
    unittest.main()
