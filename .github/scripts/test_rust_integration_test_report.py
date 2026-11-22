import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import rust_integration_test_report as reporter


class ReporterTests(unittest.TestCase):
    def test_names_are_source_derived_and_raw_text_is_excluded(self):
        raw = b'test module::known_test ... FAILED\ntest PRIVATE_TOKEN ... FAILED\npanic: PRIVATE_TOKEN\nerror: test result: FAILED\n'
        result = reporter.report(io.BytesIO(raw), 101, {"known_test": "known_test"})
        self.assertEqual(result["observedTestFunctionLabels"], ["known_test"])
        self.assertEqual(result["categories"], ["test-failure"])
        self.assertNotIn("PRIVATE_TOKEN", json.dumps(result))
        self.assertEqual(result["exitCode"], 101)

    def test_compiler_resource_and_unknown_failures(self):
        for marker, category in reporter.CATEGORIES.items():
            result = reporter.report(io.BytesIO(category + b'\n'), 101, {})
            self.assertIn(marker, result["categories"])
        self.assertEqual(reporter.report(io.BytesIO(b'PRIVATE'), 101, {})["categories"], [])

    def test_long_lines_and_many_names_are_bounded(self):
        data = b'x' * 70000 + b'test secret ... FAILED\n' + b''.join(
            f'test f{i} ... FAILED\n'.encode() for i in range(200))
        result = reporter.report(io.BytesIO(data), 101, {f'f{i}': f'f{i}' for i in range(200)})
        self.assertEqual(len(result["observedTestFunctionLabels"]), 128)
        self.assertNotIn('secret', json.dumps(result))

    def test_exact_command_exit_and_report_failure_do_not_change_gate(self):
        with patch.object(reporter, 'run_gate') as run, patch.object(reporter, 'report', side_effect=ValueError), patch('builtins.print'), patch.dict('os.environ', {'RUNNER_TEMP': '/nonexistent/exp710-report'}):
            run.return_value = (101, False, False)
            self.assertEqual(reporter.main(), 101)
            self.assertEqual(reporter.COMMAND, ['cargo', 'test', '--locked', '--test', 'all', '--test', 'argon2_shed', '--test', 'fresh_metrics'])

    def test_missing_capture_and_output_cannot_change_exit(self):
        with patch.object(reporter.tempfile, 'TemporaryFile', side_effect=OSError), patch.object(reporter, 'run_gate') as run, patch('builtins.print', side_effect=BrokenPipeError), patch.dict('os.environ', {'RUNNER_TEMP': ''}):
            for original, expected in [(0, 0), (101, 101), (-9, 137)]:
                run.return_value = (expected, False, True)
                self.assertEqual(reporter.main(), expected)

    def test_real_failed_child_preserves_exit_and_uploads_only_sanitized_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            cargo = Path(tmp) / 'cargo'
            cargo.write_text("#!/bin/sh\nprintf 'test module::fresh_node_exports_alerting_counters_at_zero ... FAILED\\nPRIVATE_RESPONSE\\ntest result: FAILED\\n'\nexit 101\n")
            cargo.chmod(0o700)
            env = {**os.environ, 'PATH': tmp + os.pathsep + os.environ.get('PATH', ''), 'RUNNER_TEMP': tmp}
            process = subprocess.run([sys.executable, str(Path(reporter.__file__).resolve())], env=env, capture_output=True, text=True)
            self.assertEqual(process.returncode, 101)
            self.assertNotIn('PRIVATE_RESPONSE', process.stdout + process.stderr)
            result = json.loads(process.stdout)
            self.assertEqual(result['observedTestFunctionLabels'], ['fresh_node_exports_alerting_counters_at_zero'])
            self.assertEqual(json.loads((Path(tmp) / 'rust-integration-test-result.json').read_text()), result)

    def test_capture_is_capped_while_child_is_fully_drained(self):
        for code in [0, 101, -9]:
            with patch.object(reporter.subprocess, 'Popen') as start, patch.object(reporter, 'MAX_CAPTURE', 32):
                child = start.return_value.__enter__.return_value
                child.stdout = io.BytesIO(b'x' * 100)
                child.wait.return_value = code
                output = io.BytesIO()
                result = reporter.run_gate(Path('.'), output, True)
                self.assertEqual(result, (137 if code == -9 else code, True, False))
                self.assertEqual(len(output.getvalue()), 32)
                self.assertEqual(child.stdout.tell(), 100)
                self.assertEqual(start.call_args.args[0], reporter.COMMAND)

    def test_source_index_and_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'tests').mkdir()
            (root / 'tests' / 'fixture.rs').write_text('async fn helper() {}\n#[tokio::test]\n#[ignore]\nasync fn known_test() {}')
            self.assertEqual(reporter.source_functions(root), {'known_test': 'known_test'})
        self.assertEqual(reporter.report(io.BytesIO(b'test known_test ... ok\n'), 0, {})['result'], 'passed')


if __name__ == '__main__':
    unittest.main()
