import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import zipfile
import subprocess
import sys
import unittest
from unittest.mock import patch
import publish_agent_oci as publication


class PublicationTests(unittest.TestCase):
    def metadata(self):
        run = {'id': publication.RUN, 'run_attempt': 1, 'head_sha': publication.HEAD,
               'event': 'workflow_dispatch', 'path': '.github/workflows/agent-runtime-qualify.yml',
               'status': 'completed', 'conclusion': 'success'}
        artifacts = [{'id': a[0], 'name': a[1], 'size_in_bytes': a[2], 'digest': 'sha256:' + a[3],
                      'expired': False, 'workflow_run': {'id': publication.RUN}} for a in publication.ARTIFACTS]
        return run, artifacts

    def test_exact_run_artifacts_and_drift(self):
        run, artifacts = self.metadata(); publication.check_source(run, artifacts)
        for key, value in [('head_sha', '0'*40), ('run_attempt', 2), ('conclusion', 'failure'), ('event', 'push')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                publication.check_source(dict(run, **{key: value}), artifacts)
        for key, value in [('id', 1), ('digest', 'sha256:'+'0'*64), ('expired', True), ('workflow_run', {'id': 1})]:
            bad = [dict(a) for a in artifacts]; bad[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                publication.check_source(run, bad)

    def test_raw_remote_bytes_only_allow_hash_proven_display_newline(self):
        raw = b'fixed metadata'; digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        self.assertTrue(publication.digest_matches(raw, digest))
        self.assertTrue(publication.digest_matches(raw+b'\n', digest))
        self.assertFalse(publication.digest_matches(raw+b'\n\n', digest))
        self.assertFalse(publication.digest_matches(raw+b' ', digest))

    def exercise(self, failure=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); calls = []; authpaths = []
            raw_manifest, raw_config = b'fixed manifest', b'fixed config'
            manifest = 'sha256:' + hashlib.sha256(raw_manifest).hexdigest()
            config = 'sha256:' + hashlib.sha256(raw_config).hexdigest()
            account = 'a'*32
            env = {'RUNNER_TEMP': temporary, 'PATH': os.environ['PATH'],
                   'CLOUDFLARE_ACCOUNT_ID': account, 'CLOUDFLARE_API_TOKEN': 'synthetic_api_token_123456789'}
            def verify(path):
                self.assertEqual(path, root); calls.append('verify')
                if failure == 'local': raise ValueError('Synthetic local drift')
            def execute(args, **kwargs):
                calls.append(args)
                self.assertNotIn(env['CLOUDFLARE_API_TOKEN'], args)
                if args == ['skopeo', '--version']: return b'skopeo version 1.13.3\n'
                if args[-1] == '--help': return b'--preserve-digests --dest-authfile --retry-times --raw --config --authfile'
                if args[0] == 'node':
                    self.assertTrue((root/'exp710-publication-attempt.json').exists())
                    self.assertIn('--push', args); self.assertIn('--pull', args)
                    self.assertEqual(args[args.index('--expiration-minutes')+1], '15')
                    if failure == 'auth': raise ValueError('Synthetic private auth error')
                    return b'{"password":"synthetic_registry_password_123456"}'
                self.assertNotIn('CLOUDFLARE_API_TOKEN', kwargs['env'])
                if 'copy' in args:
                    self.assertEqual(args[-1], 'docker://registry.cloudflare.com/'+account+'/vlpds@'+manifest)
                    self.assertIn('--preserve-digests', args)
                    self.assertEqual(args[args.index('--retry-times')+1], '0')
                    auth = Path(args[args.index('--dest-authfile')+1]); authpaths.append(auth)
                    self.assertEqual(auth.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(auth.parent.stat().st_mode & 0o777, 0o700)
                    encoded = json.loads(auth.read_text())['auths']['registry.cloudflare.com']['auth']
                    self.assertEqual(base64.b64decode(encoded), b'v1:synthetic_registry_password_123456')
                    if failure == 'copy': raise TimeoutError('Synthetic ambiguous copy')
                    Path(args[args.index('--digestfile')+1]).write_text(manifest if failure != 'digest' else 'sha256:'+'0'*64)
                    return b''
                if '--raw' in args: return b'wrong' if failure == 'remote' else raw_manifest
                if '--config' in args: return b'wrong' if failure == 'config' else raw_config
                raise AssertionError('Unexpected command')
            with patch.object(publication, 'ACCOUNT_SHA256', hashlib.sha256(account.encode()).hexdigest()), \
                 patch.object(publication, 'MANIFEST', manifest), patch.object(publication, 'CONFIG', config):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    if failure:
                        with self.assertRaises((ValueError, TimeoutError)):
                            publication.publish(root, env, execute=execute, verify=verify)
                    else:
                        report = publication.publish(root, env, execute=execute, verify=verify)
                        self.assertTrue(report['remoteVerified']); self.assertFalse(report['workerChanges'])
                        self.assertNotIn(account, json.dumps(report))
                        with self.assertRaises(FileExistsError):
                            publication.publish(root, env, execute=execute, verify=verify)
                self.assertEqual(stdout.getvalue(), '')
            self.assertTrue(all(not p.exists() for p in authpaths))
            copies = [c for c in calls if isinstance(c, list) and 'copy' in c and '--help' not in c]
            self.assertEqual(len(copies), 0 if failure in ['local', 'auth'] else 1)
            return calls

    def test_exact_copy_once_private_auth_and_readback(self):
        self.exercise()

    def test_failures_never_replay_and_remove_private_auth(self):
        for phase in ['local', 'auth', 'copy', 'digest', 'remote', 'config']:
            with self.subTest(phase=phase): self.exercise(phase)

    def test_zip_member_bounds_and_hash_refuse_before_qualification(self):
        for problem in [None, 'path', 'duplicate', 'size', 'hash']:
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); path = root/'123.zip'
                with zipfile.ZipFile(path, 'w') as bundle:
                    bundle.writestr('../escape' if problem=='path' else 'fixed.json', b'{}')
                    if problem=='duplicate': bundle.writestr('other.json', b'{}')
                raw = path.read_bytes()
                expected = '0'*64 if problem=='hash' else hashlib.sha256(raw).hexdigest()
                artifact = (123, 'fixture', len(raw), expected, 'fixed.json', 1 if problem=='size' else 16)
                with patch.object(publication, 'ARTIFACTS', (artifact,)), patch.object(publication, 'verify_local', return_value='qualified') as verify:
                    if problem:
                        with self.assertRaises(ValueError): publication.unpack(root)
                        verify.assert_not_called()
                    else:
                        self.assertEqual(publication.unpack(root), 'qualified')

    def test_cli_refusal_does_not_print_private_values(self):
        result = subprocess.run([sys.executable, publication.__file__, 'publish'],
            env={'PATH':os.environ['PATH'], 'CLOUDFLARE_API_TOKEN':'SYNTHETIC_DO_NOT_PRINT'},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 1); self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'SYNTHETIC_DO_NOT_PRINT', result.stderr)
        self.assertIn(b'Publication-only gate failed', result.stderr)

    def test_account_drift_refuses_before_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {'RUNNER_TEMP': directory, 'PATH': os.environ['PATH'],
                   'CLOUDFLARE_ACCOUNT_ID': '0'*32, 'CLOUDFLARE_API_TOKEN': 'synthetic_token_123456789'}
            with self.assertRaises(ValueError):
                publication.publish(Path(directory), env, execute=lambda *a, **k:self.fail('No credentials'), verify=lambda _:None)

    def test_manual_context_and_workflow_has_no_deploy_or_build(self):
        env = {'GITHUB_REPOSITORY':publication.REPO, 'GITHUB_REF':'refs/heads/main',
               'GITHUB_RUN_ATTEMPT':'1', 'GITHUB_WORKFLOW':'Publish qualified agent runtime (registry only)'}
        publication.context(env)
        for key in env:
            with self.subTest(key=key), self.assertRaises(ValueError): publication.context(dict(env, **{key:'wrong'}))
        source = (Path(__file__).parent.parent/'workflows/agent-runtime-publish.yml').read_text()
        self.assertIn('workflow_dispatch:', source)
        for forbidden in ['pull_request:', 'push:', 'docker build', 'wrangler deploy', 'VLPDS_DEPLOY_TOKEN', 'VLPDS_CLOUDFLARE_CONFIG_JSON']:
            self.assertNotIn(forbidden, source)
        self.assertEqual(source.count('secrets.'), 2)
        self.assertIn('actions: read', source); self.assertIn('cancel-in-progress: false', source)


if __name__ == '__main__': unittest.main()
