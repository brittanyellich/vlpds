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
PANIC_LOCATION = re.compile(
    rb"^thread '[^\r\n']{1,512}'(?: \([0-9]{1,20}\))? panicked at "
    rb"(tests/[A-Za-z0-9_/-]{1,240}\.rs):([1-9][0-9]{0,6}):([1-9][0-9]{0,6}):\r?\n$")
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


def source_locations(root):
    # Only checked-out test files, never paths copied from subprocess output.
    tests = (root / "tests").resolve()
    paths = {}
    tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", "--", "tests"])
    for raw in tracked.split(b"\0"):
        relative = raw.decode("utf-8")
        path = root / relative
        if (path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(tests)
                and re.fullmatch(r"tests/[A-Za-z0-9_/-]{1,240}\.rs", relative)):
            paths[relative] = len(path.read_text(encoding="utf-8").splitlines())
    return paths


def report(stream, code, known, locations=None):
    categories, failed, observed_locations = set(), set(), set()
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
        location = PANIC_LOCATION.fullmatch(line)
        if location and len(observed_locations) < 128:
            path = location[1].decode("ascii")
            number = int(location[2])
            if path in (locations or {}) and number <= locations[path]:
                observed_locations.add((path, number))
    return {"version": 1, "kind": "rust-integration-test-result",
            "result": "passed" if code == 0 else "failed", "exitCode": code,
            "categories": sorted(categories), "observedTestFunctionLabels": sorted(failed),
            "observedPanicLocations": [{"path": path, "line": number} for path, number in sorted(observed_locations)],
            "locationsAreUnverifiedCandidates": True,
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
        known, locations = source_functions(root), source_locations(root)
        index_unavailable = False
    except Exception:
        known, locations, index_unavailable = {}, {}, True
    try:
        output = tempfile.TemporaryFile()
        captured = True
    except OSError:
        output = open(os.devnull, "w+b")
        captured = False
    with output:
        code, truncated, unavailable = run_gate(root, output, captured)
        try:
            if unavailable or index_unavailable:
                raise OSError("Capture unavailable")
            result = report(output, code, known, locations)
        except Exception:
            result = {"version": 1, "kind": "rust-integration-test-result",
                      "result": "passed" if code == 0 else "failed", "exitCode": code,
                      "categories": ["report-unavailable"], "observedTestFunctionLabels": [],
                      "observedPanicLocations": [], "locationsAreUnverifiedCandidates": True,
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
