# EXP-710 digest-only OFF staging and recovery

This includes a **manual-only production transport, not approval to execute**.
`off-staging-plan.mjs` remains a pure injected core. The transport and workflow
are qualified against synthetic providers only. Do not dispatch the generic deploy workflow
as a substitute: its rollback republishes current source rather than selecting
the original Worker version, and it does not validate the restart ACK contract.

## Reviewed inputs

Candidate revision: `703c118c66277ca42c45808a2f6cc620429c6718`.
Manifest: `sha256:ea8627d4e368ca3bd3eafaf8c24765fa3db00c6f0c182853c4feda6bac47a488`.
Config: `sha256:0c74fc9a23efdc50ea7b92359fe806ef0702dee29275f4a92337e9188c8e873a`.
Build `45748259449`, OCI artifact `15084043877`; authenticated pull-only
readback `45773069113` matched both digests. **No publication is needed.**

Fresh inspection `45840841308` / receipt artifact `15128800006` verified
Worker `93724e8b-1a4e-41ab-ba5a-1759bfb8a0cc`, script etag
`88f6a917a64c75dda70dd40bb76cc74c8607790400fd50349095ec7fe615dc42`,
23 bindings, OFF, no lease, healthy runtime
`sha256:2e254f9394937be2141e192b715f88867a349bbd85c80d9279e435282b11161d`.
This observation is historical input, not a reusable freshness grant.
The name/type hash is
`0fc25600babf6b573a96519018b704a676c59723f09f83ba89de0b27f3c0c5ad`.
Account is bound by SHA-256 fingerprint in the module, never an arbitrary registry.

## Manual transport procedure

1. Verify reviewed workflow/source pins and authenticated candidate receipt,
   acquire the single production Actions concurrency group, confirm the operator
   has frozen dashboard/API/CLI configuration writes, and durably claim one
   operation ID. No automatic retry or overlapping watcher. Stage and recovery
   require separate operation grants, each with a bounded expiry.
2. Fetch metadata/status/public health independently, before and immediately
   after preparation. Require the exact baseline above, qualified desired/current
   image, all 23 name/types, exact OFF agent variables, no lease/pilot secrets,
   stable ordinary binding values, UI and disabled Card. Each snapshot must
   finish within 30 seconds; capture completion time locally. Stop on drift.
3. Use `prepareOffStage` with protected config and existing secrets. It refuses
   a foreign account, `keep_vars`, stale lease/consent/pilot policy and secrets
   in vars; preserves ordinary configuration; replaces the image only with the
   already published candidate digest. Upload **candidate revision's Worker
   source**, not current main's later source. No Container build, copy, tags,
   migration, durable-object replacement or registry-auth operation.
4. Use pinned Wrangler `4.158.0` **offline only** to bundle the candidate.
   A live `deploy --containers-rollout none` preserves the existing image map;
   normal live CLI deploy also retries writes and touches non-versioned settings.
   Neither is the staging transport. The direct API first polls the supported
   managed-image preparation endpoint for candidate and rollback images within
   one shared 90-second budget, only while it
   explicitly returns `pending`; errors are not retried. This is runtime image
   preparation, not registry publication, build or credential minting.
   Upload one multipart Worker version using the prepared bytes and exact named
   image map, then activate that exact UUID at 100% with immediate DO code update.
   No routes, non-versioned settings or Container application API is changed.
   Strict inheritance is allowed only when the latest uploaded version equals
   the baseline; verify the new version's resolved bindings before activation.
   After activation fetch active `content/v2`, require only `index.js`, and
   compare module bytes with the prepared bundle hash. Keep that hash separate
   from the server ETag. Metadata before/after content must be stable.
   A known old deployment may be observed for up to 30 seconds of read-only
   propagation checks; unknown versions/code/bindings are immediate drift.
   On upload/activation ambiguity, perform one bounded read-only reconciliation
   attempt to retain a byte-verified recovery checkpoint, then **stop regardless
   of reconciliation success**, without restart or any write replay.
5. Send **one** authenticated `/_deploy/restart` with exact `X-Deploy-Image`.
   Accept only HTTP 202 JSON with `desired` equal to the candidate, `starting`
   true and boolean `restarted`. Then bounded GET-only readiness must establish
   exact current/desired digest, running=true, OFF/no lease/23 unchanged bindings,
   health `1.3.0+703c118c66277ca42c45808a2f6cc620429c6718`, UI and Card 404.
   A cold pre-restart image mismatch is expected after changing the image map;
   do not reuse `PilotProvider.restart` unchanged: it requires old=current=desired.
6. Keep a receipt with the new Worker UUID/script, ordinary binding hash,
   both image pins, one-write intent/results and independent readbacks. This
   staged receipt is required to guard recovery against competing changes.

## Exact recovery

With an explicit recovery grant and the write freeze still in place, require
the staged Worker UUID/script and unchanged ordinary bindings, OFF and no lease.
Recheck managed rollback-image availability within a bounded 90-second budget
before selecting the old Worker. Recovery must be possible when candidate health is failing; health failure
alone is not configuration drift. Select the **existing** baseline Worker at
100% using the supported Workers deployment API payload from
`rollbackDeployment()`. Verify active UUID/script/OFF bindings and desired
rollback digest, then send one qualified restart and independently verify the
old current digest, health revision `21117d08d00b6d1bb95430c0cc4a89eb5ec59785`, UI,
Card 404 and all baseline bindings. Never claim a newly uploaded Worker is
the historical UUID. Unknown source version/configuration or ambiguous writes
require read-only reconciliation and an operator decision, not blind rollback.

Cloudflare documents that a rollback selects the old Worker at 100%, while
named image maps follow the Worker version. The running Container remains on
its startup image until application-controlled restart:

- [Worker rollbacks](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)
- [Named image updates](https://developers.cloudflare.com/containers/guides/image-management/#roll-out-a-named-image-update)
- [Strict version upload and inheritance](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/create/)
- [Create Worker deployment API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/create/)

## Transport guards and execution boundary

`cloudflare-off-staging.yml` runs only on manual dispatch, main, attempt 1,
with explicit `exclusive_window=true` and a reviewed-head input equal to the
actual main SHA. It uses the existing production
concurrency group and environment, existing secrets, and the fixed candidate
checkout. It has no PR, push or scheduled trigger. No workflow was dispatched
during development.

The runner enforces the account fingerprint and authenticates the prior registry
receipt, source run, artifact identity, ZIP size/digest and single JSON member.
An expired artifact stops preflight; it does not request new registry access.
Protected plain-text vars must equal independent live metadata before upload.
Configuration permits only the known hosts/routes, migration and DO class;
unexpected build/assets/migration/compatibility configuration stops execution.

A GitHub Deployment record is the durable, one-shot intent for this candidate
and operation. Its existence blocks a second operation across fresh runners,
including after an ambiguous write. Listing then creating is not atomic; the
shared concurrency group and actual operator write freeze remain mandatory.
GitHub deployment-record/status writes are bookkeeping, not provider actions.
The next execution approval must include that bookkeeping. No repository workflow
subscribes to deployment events in this reviewed revision.

Snapshots have a 30-second aggregate deadline, individual requests are bounded,
and aborted async continuations cannot start later requests. Restart is one
75-second POST, followed by up to 90 seconds of GET-only readiness. No POST is
replayed. The bounded grant is rechecked before each provider write, and metadata
is reread after the durable claim immediately before upload/recovery.

After the selected Worker source, image map and OFF bindings have been verified,
a sanitized recovery checkpoint is retained before restart. A failed or cancelled
stage with that authenticated checkpoint may be recovered explicitly. Upload
ambiguity has no invented recovery identity: a single bounded read-only check
may authenticate a checkpoint, but execution always stops. If it cannot verify
the identity, further read-only reconciliation needs an operator decision. Recovery accepts a stage from another main revision
only if the complete execution-code fingerprint is unchanged. An unrelated main
commit does not strand recovery; changed transport code requires new review.

The core's synthetic account/observation seam is not authentication. Only the
production runner binds context, account, evidence and durable ownership.

Actual Worker ACK plus independent OFF configuration/readiness is **not native
process self-attestation**; the receipt labels that distinction explicitly.
No native OFF restart has been observed during this local work. A native
self-attestation requirement would need an additional runtime endpoint.

The next approval request is executable only after the parent and transport PRs
are reviewed, merged and qualified: one digest-only OFF staging upload/restart,
bounded candidate/rollback runtime image preparation (no registry transfer), GitHub durable
intent/status bookkeeping, and explicitly scoped
recovery to Worker `93724e8b` plus image `2e254f` if required, during a confirmed
exclusive write window. No activation, enrollment, token mint, publication,
permanent revocation or unrelated settings changes. Do not request execution
approval before those gates pass. The actual stage and recovery have not run.
