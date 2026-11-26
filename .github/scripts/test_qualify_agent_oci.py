import copy
import hashlib
import gzip
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from qualify_agent_oci import REVISION, qualify, load_receipt


class QualificationTests(unittest.TestCase):
    def archive(self, directory, *, wrong_config=False, corrupt_layer=False, duplicate=False, extra_manifest=False, bad_config_media=False, bad_layer_media=False, wrong_diff_id=False, compressed=False):
        entries = {}

        def blob(value, media):
            raw = json.dumps(value).encode() if isinstance(value, dict) else value
            digest = hashlib.sha256(raw).hexdigest()
            entries['blobs/sha256/' + digest] = raw
            return {'digest': 'sha256:' + digest, 'size': len(raw), 'mediaType': media}

        raw_layer = b'synthetic layer'
        diff_id = 'sha256:' + ('0' * 64 if wrong_diff_id else hashlib.sha256(raw_layer).hexdigest())
        config = blob({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': [diff_id]}}, 'application/vnd.oci.image.config.v1+json')
        layer = blob(gzip.compress(raw_layer) if compressed else raw_layer, 'application/vnd.oci.image.layer.v1.tar+gzip' if compressed else 'application/vnd.oci.image.layer.v1.tar')
        if bad_config_media:
            config['mediaType'] = 'application/octet-stream'
        if bad_layer_media:
            layer['mediaType'] = 'application/octet-stream'
        manifest = blob({'schemaVersion': 2, 'config': config, 'layers': [layer]}, 'application/vnd.oci.image.manifest.v1+json')
        entries['oci-layout'] = b'{"imageLayoutVersion":"1.0.0"}'
        entries['index.json'] = json.dumps({'schemaVersion': 2, 'manifests': [manifest] * (2 if extra_manifest else 1)}).encode()
        if corrupt_layer:
            entries['blobs/sha256/' + layer['digest'][7:]] = b'corrupted layer'
        archive = pathlib.Path(directory) / 'candidate.tar'
        with tarfile.open(archive, 'w') as tar:
            for name, raw in entries.items():
                info = tarfile.TarInfo(name); info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
            if duplicate:
                info = tarfile.TarInfo('index.json'); info.size = len(entries['index.json'])
                tar.addfile(info, io.BytesIO(entries['index.json']))
        receipt = {'version': 1, 'revision': REVISION, 'runtime': 'agent-a2a', 'platform': 'linux/amd64',
                   'capabilityVerified': True, 'dockerClientVersion': '28.0.0', 'configDigest': 'sha256:' + '0' * 64 if wrong_config else config['digest'],
                   'imageId': config['digest']}
        return archive, receipt, manifest

    def test_exact_export_binds_qualified_config_and_streamed_layers(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, receipt, manifest = self.archive(directory)
            result = qualify(archive, receipt)
            self.assertEqual(result['manifestDigest'], manifest['digest'])
            self.assertEqual(result['configDigest'], receipt['configDigest'])
            self.assertFalse(result['registryPublished'])
            self.assertEqual(result['archiveSha256'], hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_gzip_layer_binds_uncompressed_rootfs(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, receipt, _ = self.archive(directory, compressed=True)
            self.assertTrue(qualify(archive, receipt)['capabilityVerified'])

    def test_wrong_export_corrupt_layer_duplicate_or_multiple_candidates_deny(self):
        for option in ['wrong_config', 'corrupt_layer', 'duplicate', 'extra_manifest', 'bad_config_media', 'bad_layer_media', 'wrong_diff_id']:
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                archive, receipt, _ = self.archive(directory, **{option: True})
                with self.assertRaises(ValueError):
                    qualify(archive, receipt)

    def test_unqualified_wrong_revision_runtime_or_platform_deny(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, receipt, _ = self.archive(directory)
            for key, value in [('revision', '8fb5949c400018146ef58e594697859403c0d247'), ('revision', '0' * 40), ('runtime', 'pds-runtime'), ('platform', 'linux/arm64'), ('capabilityVerified', False), ('imageId', 'sha256:' + '1' * 64)]:
                bad = copy.deepcopy(receipt); bad[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    qualify(archive, bad)

    def test_receipt_size_and_unknown_fields_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, receipt, _ = self.archive(directory)
            receipt['extra'] = 'unexpected'
            with self.assertRaises(ValueError):
                qualify(archive, receipt)
            path = pathlib.Path(directory) / 'receipt.json'
            path.write_bytes(b' ' * 8193)
            with self.assertRaises(ValueError):
                load_receipt(path)

    def test_manual_workflow_never_requests_provider_or_registry_writes(self):
        source = (pathlib.Path(__file__).parent.parent / 'workflows/agent-runtime-qualify.yml').read_text()
        self.assertIn('workflow_dispatch:', source)
        self.assertNotIn('pull_request:', source)
        self.assertNotIn('push:', source)
        self.assertNotIn('secrets.', source)
        self.assertNotIn('environment:', source)
        self.assertNotIn('packages: write', source)
        self.assertIn('contents: read', source)
        self.assertEqual(REVISION, '703c118c66277ca42c45808a2f6cc620429c6718')
        self.assertIn('ref: ' + REVISION, source)
        self.assertIn('a5578cb57829d36f4f2c0bb7f1b507af8783a023', source)
        self.assertIn('test/hosted-consent-supervisor.test.mjs', source)
        self.assertIn('test/agent-runtime.test.ts', source)
        self.assertIn('test/deploy-artifact.test.mjs', source)
        self.assertIn('npm ci --ignore-scripts', source)
        self.assertIn('npm run typecheck', source)
        self.assertIn('--build-arg VLPDS_RUNTIME_STAGE=agent-a2a', source)
        self.assertIn('type=oci,dest=', source)
        self.assertNotIn('--push', source)


if __name__ == '__main__':
    unittest.main()
