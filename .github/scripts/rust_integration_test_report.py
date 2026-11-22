"""Run the existing Rust integration gate; retain no raw subprocess output."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

COMMAND = ["cargo", "test", "--locked", "--test", "all", "--test", "argon2_shed", "--test", "fresh_metrics"]
MAX_CAPTURE = 8 * 1024 * 1024
CATEGORIES = {
    "compiler-error": b"could not compile",
    "test-failure": b"test result: FAILED",
    "process-killed": b"signal: 9",
    "storage-full": b"No space left on device",
    "build-script-failure": b"failed to run custom build command",
    "dependency-download-failure": b"failed to download",
}
FAILED = re.compile(rb"^test ([A-Za-z_][A-Za-z0-9_:]{0,511}) \.\.\. FAILED\s*$")
TEST_FUNCTION = re.compile(
    r"^\s*#\[(?:tokio::)?test(?:\([^\]]*\))?\]\s*"
    r"(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<|\()", re.MULTILINE)



def source_functions(root):
    # Output identifiers come from attributed test source, never arbitrary text.
    # A matching output line is only a candidate label, not harness attestation.
    names = set()
    for path in (root / "tests").rglob("*.rs"):
        names.update(TEST_FUNCTION.findall(path.read_text(encoding="utf-8")))
    return {name: name for name in names}


def report(stream, code, known):
    categories, failed = set(), set()
    stream.seek(0)
    while True:
        line = stream.readline(65537)
        if not line:
            break
        if len(line) > 65536:
            while line and not line.endswith(b"\n"):
                line = stream.readline(65537)
            continue
        for category, marker in CATEGORIES.items():
            if marker in line:
                categories.add(category)
        match = FAILED.fullmatch(line)
        if match:
            leaf = match[1].decode("ascii").split("::")[-1]
            if leaf in known and len(failed) < 128:
                failed.add(known[leaf])
    return {"version": 1, "kind": "rust-integration-test-result",
            "result": "passed" if code == 0 else "failed", "exitCode": code,
            "categories": sorted(categories), "observedTestFunctionLabels": sorted(failed),
            "rawOutputRetained": False}


def run_gate(root, output, capture):
    kept, truncated, unavailable = 0, False, not capture
    try:
        with subprocess.Popen(COMMAND, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                remaining = MAX_CAPTURE - kept
                if len(chunk) > remaining:
                    truncated = True
                retained = chunk[:remaining]
                kept += len(retained)
                if capture and retained:
                    try:
                        output.write(retained)
                    except OSError:
                        capture = False
                        unavailable = True
                # Always drain the rest, even after the storage cap or sink failure.
            code = process.wait()
            return (code if code >= 0 else 128 - code), truncated, unavailable
    except OSError:
        return 127, truncated, True


def main():
    root = Path(__file__).resolve().parents[2]
    try:
        output = tempfile.TemporaryFile()
        captured = True
    except OSError:
        output = open(os.devnull, "w+b")
        captured = False
    with output:
        code, truncated, unavailable = run_gate(root, output, captured)
        try:
            if unavailable:
                raise OSError("Capture unavailable")
            result = report(output, code, source_functions(root))
        except Exception:
            result = {"version": 1, "kind": "rust-integration-test-result",
                      "result": "passed" if code == 0 else "failed", "exitCode": code,
                      "categories": ["report-unavailable"], "observedTestFunctionLabels": [],
                      "rawOutputRetained": False}
    result["labelsAreUnverifiedCandidates"] = True
    result["captureTruncated"] = truncated
    result["captureLimitBytes"] = MAX_CAPTURE
    try:
        print(json.dumps(result))
    except OSError:
        pass
    destination = os.environ.get("RUNNER_TEMP")
    if destination and Path(destination).is_absolute():
        try:
            path = Path(destination) / "rust-integration-test-result.json"
            with path.open("x", encoding="utf-8") as receipt:
                json.dump(result, receipt)
        except OSError:
            # Observability must never turn a failed gate green or vice versa.
            pass
    return code


if __name__ == "__main__":
    sys.exit(main())
