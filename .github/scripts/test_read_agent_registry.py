import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import read_agent_registry as readback


class ReadbackTests(unittest.TestCase):
    def exercise(self, failure=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); calls = []; owned = []
            account = 'a' * 32; secret = 'synthetic_private_token_12345'
            raw_manifest, raw_config = b'fixed manifest', b'{"os":"linux","architecture":"amd64"}'
            env = {'PATH': os.environ['PATH'], 'RUNNER_TEMP': directory,
                   'CLOUDFLARE_ACCOUNT_ID': account, 'CLOUDFLARE_API_TOKEN': secret}
            def verify(path):
                self.assertEqual(path, root)
                if failure == 'local': raise ValueError('local')
            def execute(args, **kwargs):
                calls.append(args); self.assertNotIn(secret, args)
                self.assertNotIn('copy', args); self.assertNotIn('--push', args)
                if args == ['skopeo', '--version']: return b'skopeo version 1.13.3'
                if args[-1] == '--help': return b'--raw --config --authfile --retry-times'
                if args[0] == 'node':
                    self.assertIn('--pull', args)
                    self.assertEqual(args[args.index('--expiration-minutes')+1], '15')
                    self.assertEqual(kwargs['env']['CLOUDFLARE_API_TOKEN'], secret)
                    if failure == 'auth': raise TimeoutError(secret)
                    return b'{"password":"synthetic_registry_password_12345"}'
                self.assertNotIn('CLOUDFLARE_API_TOKEN', kwargs['env'])
                self.assertIn('--tls-verify=true', args); self.assertIn('--raw', args)
                self.assertEqual(args[args.index('--retry-times')+1], '0')
                auth = Path(args[args.index('--authfile')+1]); owned.append(auth)
                self.assertEqual(auth.stat().st_mode & 0o777, 0o600)
                self.assertEqual(auth.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(args[-1], 'docker://registry.cloudflare.com/'+account+'/vlpds@'+readback.MANIFEST)
                stage = 'config' if '--config' in args else 'manifest'
                if failure == stage: raise TimeoutError(secret)
                if failure == stage+'-drift': return b'wrong'
                return raw_config if stage == 'config' else raw_manifest
            pins = {'ACCOUNT_SHA256':hashlib.sha256(account.encode()).hexdigest(),
                    'MANIFEST':'sha256:'+hashlib.sha256(raw_manifest).hexdigest(),
                    'CONFIG':'sha256:'+hashlib.sha256(raw_config).hexdigest()}
            with patch.multiple(readback, **pins):
                if failure == 'local':
                    with self.assertRaises(ValueError): readback.readback(root,env,execute,verify)
                    self.assertEqual(calls,[]); return
                report = readback.readback(root,env,execute,verify)
                self.assertEqual(report['result'], 'verified' if failure is None else 'unverified')
                self.assertTrue(report['temporaryAuthRemoved'])
                self.assertFalse(report['copyPerformed']); self.assertFalse(report['retryPerformed'])
                self.assertNotIn(secret,json.dumps(report)); self.assertNotIn(account,json.dumps(report))
                self.assertLess((root/'exp710-readback-receipt.json').stat().st_size,8192)
                before = len(calls)
                with self.assertRaises(FileExistsError): readback.readback(root,env,execute,verify)
                self.assertEqual(len(calls),before)
            self.assertTrue(all(not p.exists() for p in owned))
            self.assertEqual(sum(c[0]=='node' for c in calls),1)
            if failure: self.assertEqual(report['stage'], failure.replace('-drift',''))

    def test_exact_read_only_success_and_no_replay(self): self.exercise()

    def test_failures_stop_without_retry_and_cleanup(self):
        for failure in ['local','auth','manifest','manifest-drift','config','config-drift']:
            with self.subTest(failure=failure): self.exercise(failure)

    def test_account_drift_before_auth(self):
        with tempfile.TemporaryDirectory() as d:
            env={'RUNNER_TEMP':d,'PATH':os.environ['PATH'],'CLOUDFLARE_ACCOUNT_ID':'0'*32,
                 'CLOUDFLARE_API_TOKEN':'synthetic_token_1234567890'}
            with self.assertRaises(ValueError):
                readback.readback(Path(d),env,execute=lambda *a,**k:self.fail('No auth'),verify=lambda _:None)

    def test_context(self):
        env={'GITHUB_REPOSITORY':readback.REPO,'GITHUB_REF':'refs/heads/main','GITHUB_RUN_ATTEMPT':'1',
             'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_WORKFLOW':readback.WORKFLOW}
        readback.context(env)
        for key in env:
            with self.subTest(key=key),self.assertRaises(ValueError):readback.context(dict(env,**{key:'wrong'}))

    def test_workflow_and_source_no_write_path(self):
        root=Path(__file__).resolve().parents[2]
        source=(root/'.github/workflows/agent-runtime-readback.yml').read_text()
        self.assertIn('workflow_dispatch:',source);self.assertIn('cancel-in-progress: false',source)
        self.assertEqual(source.count('secrets.'),2)
        self.assertIn('read_agent_registry.py verify',source);self.assertIn('read_agent_registry.py read',source)
        for forbidden in ['pull_request:', 'push:', 'docker build', 'wrangler deploy','publish_agent_oci.py publish']:
            self.assertNotIn(forbidden,source)
        code=(root/'.github/scripts/read_agent_registry.py').read_text()
        self.assertNotIn("'--push'",code);self.assertNotIn("'copy'",code)


if __name__=='__main__':unittest.main()
