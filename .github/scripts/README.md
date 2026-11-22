# Sanitized Rust integration result

`rust_integration_test_report.py` runs exactly:

```
cargo test --locked --test all --test argon2_shed --test fresh_metrics
```

It propagates Cargo's exit status. Raw combined output is held in an unnamed
private temporary file capped at8MiB, then closed; it is never printed or uploaded. The fixed
JSON receipt contains only result/exit code, allowlisted failure categories and
observed candidate function labels validated against attributed Rust test source. Combined child output cannot authenticate harness lines: a test can print a
lookalike label. `labelsAreUnverifiedCandidates` is always true; labels must be
corroborated before attributing a defect and never control the gate. Names
can be incomplete (for example, compiler failure, interleaved harness output or
generated tests). Panic text, raw diagnostics, arbitrary names and response bodies
are excluded. Output after the cap is drained without storage; `captureTruncated`
marks incomplete capture. Parsing and receipt-write failure do not change the test gate.

The workflow retains only this JSON on integration failure. This adds evidence,
not a retry or a test workaround. Unit fixtures verify redaction, output bounds,
source name validation, exact command and exit preservation.

EXP-710 main `ea95d19` failed the integration step twice with only exit101 in
structured annotations and no artifacts. Its PR and main trees/workflows match;
cache save policy differs by event, but no cause is established. The same targets
passed locally on macOS (1259 suite tests plus two dedicated tests); the matching
Ubuntu24.04/Rust1.100/Go1.27.3 CI run remains the recovery gate. This change does
not authorize another unchanged-build rerun, credentials or production activation.
