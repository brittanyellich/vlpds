# EXP-710 digest-only OFF staging and recovery

This is a locally qualified transition contract, **not an enabled deployment
workflow**. `off-staging-plan.mjs` has no CLI, network, credentials, process
selection or default production transport. Its injected transport is exercised
only with synthetic observations. Do not dispatch the generic deploy workflow
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

## Procedure to implement in the production transport

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
   source**, not current main's later source. No Dockerfile/build, copy, tags,
   migration, durable-object replacement or registry-auth operation.
4. Use existing `publishPilotWorker` pinned Wrangler `4.158.0`, named-image
   `--containers-rollout none` and explicit DO code mode `immediate`. Record its
   structured version ACK bound to the precomputed prepared upload script hash,
   candidate revision and both OCI digests. Authoritative script readback must
   match that prepared hash. A timeout/invalid ACK is ambiguous: stop and inspect,
   never repeat upload automatically. Read the authoritative active Worker,
   binding set and desired candidate image before restarting.
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
Recovery must be possible when candidate health is failing; health failure
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
- [Create Worker deployment API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/create/)

## Remaining execution boundary

The existing publisher and actual Worker restart ACK fixture are supported
building blocks. A production transport still needs reviewed fixed-source
checkout/config upload, bounded snapshot/readiness implementation, the exact
deployment API adapter, durable operation ownership and receipt persistence.
This PR does not connect them to a production entry point. The core's account
argument and observations are contracts, not authentication: production must
call the account-bound `prepareOffStage` and authenticate every observation.

Actual Worker ACK plus independent OFF configuration/readiness is **not native
process self-attestation**; the receipt labels that distinction explicitly.
No native OFF restart has been observed during this local work. A native
self-attestation requirement would need an additional runtime endpoint.

The next approval request is executable only after that transport is reviewed
and merged: one digest-only OFF staging upload/restart, and explicitly scoped
recovery to Worker `93724e8b` plus image `2e254f` if required, during a confirmed
exclusive write window. No activation, enrollment, token mint, publication,
permanent revocation or unrelated settings changes. Do not request execution
approval against this contract-only PR.
