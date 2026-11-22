# Card readiness observations and next test

The qualified release image was tested locally by its exact manifest
`sha256:2e254f9394937be2141e192b715f88867a349bbd85c80d9279e435282b11161d`.
Raw OCI bytes bound it to config
`sha256:f37795cbec5286e8967c7d3cfa464a33f82079835ca1ba7b2de6b1ae0899ddce`.
The actual release supervisor and native binary returned HTTP200 and the exact
frozen signed Card JSON with production origin, audience and runtime arguments.
Storage was a disposable local Moto S3 emulator with an active synthetic account;
`--dev-mode` supplied local storage defaults. The private bridge was a stub that
could never dispatch. The unchanged guarded verifier fetched public PLC metadata.
No production storage, credentials, records or runtime settings were used.

The same process returned200 through the actual Worker/DO source with a local
container transport shim. Expired lease admission returned404 before native.
This is not evidence of managed Cloudflare environment propagation. Owned test
containers, emulator storage and network were removed. Temporary pull credential
files were removed without changing persistent Docker login; the credential had
15-minute expiry. Local public receipts remain in the operator's review records.

## What a failure receipt now means

Previously, enabled-mode404 and502/503/504 all became `card-pending`. New fixed
codes retain the HTTP status. Only a JSON-media-type response with an exact single-field native-looking error object can
add `agent-unavailable` (404) or `trust-unavailable` (503). All other responses
remain `other`; body text is never retained. These are observed response labels,
not independent attestations of native process mode or trust state. Unknown
failures, retry count, timeout, readiness, caller auth and cleanup remain unchanged.

A404 with `agent-unavailable` localizes the observed native account gate. A503
with `trust-unavailable` localizes the native Card trust gate, but does not identify
which trust check failed. An unrecognized404 can still be edge admission, a missing
native mount or another upstream response. No response alone proves stale mode.

## Reuse the bounded workflow without Otto

No new workflow is needed for a readiness-only observation. The existing
`cloudflare-agent-pilot.yml` can perform its full guarded sequence without invoking
an Otto consumer or private Terminal. It still enables the Otto-allowlisted route
for its bounded lease and therefore requires separate explicit production-run
approval; this document and PR do not authorize dispatch.

Prerequisites: exact merged main and green CI, fresh authenticated OFF/image/key/
binding checks against the pinned baseline, no competing production workflow,
one fresh org/profile-bound scoped token with same-value validation, independent
bridge key, approved private stdin provisioning, and a custodian available to
revoke. Use one dispatch with persisted intent/run ID, never an automatic retry.
Do not substitute dummy credentials or bypass token/lease/auth gates.

On success, authenticate the existing ready artifact and record readiness only;
do not launch Otto. Let the existing wait finish its bounded window and the
always-OFF/cleanup steps run. Do not cancel merely to shorten the window: runner
loss/cancel can prevent reconciliation. On any failure, preserve only sanitized
failure evidence, stop without retry and verify OFF/no lease/baseline bindings,
remove temporary Actions secrets and revoke the exact credential with custodian
confirmation. Lease expiration closes admission even if the runner is lost, but
is not proof that bindings were removed.

The exact initial OFF pin is05c661c2 from authenticated inspection44938702703.
Historical evidence supports that pin; it cannot replace fresh checks before a
new run. If the next result is still an ambiguous404, the next tier is a separately
reviewed authenticated direct-container status/mode projection, not relaxed gates
or raw log retrieval. No Worker/native change is required for this PR.
