# EXP-710 bounded activation candidate

This workflow is a new production mutation path, not an extension of the status
or restart-only workflows. Do not dispatch it until exact-head review/CI, merge,
operator and Otto readiness, and approved credential custody are complete.

The fixed artifact is Cloudflare platform digest
`2e254f9394937be2141e192b715f88867a349bbd85c80d9279e435282b11161d`,
Linux AMD64, native-profile-v1, qualified source21117d08. Guarded run44819495762
passed its exact current/desired/running/OFF checks. This does not retroactively
resolve the earlier unrelated8c710/fbf39 mapping. No image build, image push,
account data change or public repository record write exists in this workflow.

## Custody and prerequisites

1. Freeze/review the workflow head. Require unchanged lockfile and Worker modules other than the separately
   qualified lease-only index.ts/runtime.ts versus qualified21117d08. Pin
   the exact reviewed Worker qualification file hashes before publishing. Read fresh authenticated current/desired/running,
   exact requalified clean OFF Worker8d335d21-6498-43ae-a42d-56c02368782e, current Card key,
   public health/UI/Card404. Initial Worker must have no pilot secret bindings.
2. Have Otto's reviewed caller harness ready first. It must keep operator unlock
   and fresh service JWT local/private. No JWT or passphrase in workflow inputs,
   receipts, logs, chat or artifacts. Only fixed read-only identity requests.
3. Identity-test custodian mints an org-bound org:execute token for profile
   prf_642a5cf465fa4528a8f7e075f29557c4,900-second sliding idle and3600-second
   absolute maximum. Expected org is independently pinned from the prior revoked
   actual fixture: c74cb336bbed5cca02db72fff3998b10f977c015aab112f0878d421d55d15ecf.
   Verify again using available read-only owner metadata before mint. This is
   separate from caller identity, endorsement proof and Card ownership.
4. Keep the one-time value out of API output/logs. Via approved owner-controlled
   stdin, set only GitHub production-environment secrets VLPDS_AGENT_KODY_TOKEN
   and an independently random64-lowercase-hex VLPDS_AGENT_BRIDGE_KEY. Do not use
   argv/env-file or repository files to transfer them. Any owner0600 temporary
   custody files must be removed after transfer/revocation. Existing CF/deploy
   secrets remain unchanged. Secret creation is separately audited by owner.
5. Pass *metadata only*: id,created_at,expires_at,max_expires_at,idle_ttl_seconds,
   profile_id,org_binding,org_id,scopes,status. ISO UTC timestamps are normalized;
   unknown fields (including token) are rejected. Opaque token IDs are preserved
   exactly for tokenGet/revoke. Fresh mint <=600seconds old at preflight; provision
   must therefore begin promptly after mint. No implicit refresh or extension. Immediately before provision, call fixed
   https://api.kody.codes/v1/tokens/current with the exact candidate bearer; reject
   wrapper/unknown fields and compare authoritative id/org/profile/scopes/status/
   absolute expiry to the custodian receipt. Sliding idle can move within the
   server maximum, but it cannot move the fixed pilot deadline.
6. card_json is the exact local signed artifact file bytes SHA256f02d7b8e...,
   not a newly generated Card. Previously independent Node/native crypto checked
   frozen unsigned JCS0239e2b2...; current published key must still match. HTTP
   uses JSON serialization, so HTTP raw bytes need not match the local file hash.

## Mutation and window

Manual main-only run_attempt1, protected production environment, and the same
production concurrency lock serialize this with deployment/restart operations.
No secrets are passed to install/test/upload steps. Pilot token/key exist only
in the provision step; the private fixed API transport receives them in memory.

Private cross-step state has a domain-separated HMAC under the existing deploy
secret; identity/phase/deadline/baseline tampering is rejected. This is not a
security boundary against a compromised runner with access to process secrets.

The pinned Wrangler4.158.0 implementation uses Workers secrets-bulk PATCH with
application/merge-patch+json. Our adapter uses that same fixed account/script API
with exactly two secret_text entries, deadline/body cap/no redirect/no retry and
sanitized error. It performs no CLI execution, credential inheritance, secret
file or raw log output. Wiping a Buffer does not zeroize JavaScript strings or
provider plaintext custody. API success is insufficient: independent version and
binding readback must remain OFF, with all ordinary bindings unchanged.

Activation prepares the existing production config preserving storage, DO,
routes and ordinary secrets, pins the same qualified image and adds only fixed
Otto/Card/public agent vars. Pinned installed Wrangler publishes that reviewed
Worker config with containers-rollout none. No runtime rebuild or image push.
Native process configuration switches via one expected-image guarded restart.
Ambiguous activation never gets an automatic second activation POST. OFF rollback
is a distinct safety transition, not an activation retry.

The acceptance deadline and fixed AGENT_A2A_EXPIRES_AT lease are preflight time+600seconds, inside the approved
900idle/3600max credential envelope. At least300seconds must remain before
activation begins. Read-only readiness polls retry only transient provider/boot
failures; permanent configuration/image/Card drift stops immediately. While
active, monitor exact image/Worker/Card/health repeatedly until the deadline.

A successful activation step writes only a sanitized readiness artifact containing
run/head/repository, exact digest and qualified revision, observed active Worker,
fixed caller/recipient/profile, Card pin/hash/JCS and checkedAt/deadline. Otto must
verify it through authenticated GitHub run/job/step/artifact APIs at the approved
head and verify the live Card independently. A forwarded JSON body or boolean is
not authority. The overall workflow can be in progress during the acceptance
window; the named activation and receipt-upload steps must already have passed.

## Acceptance and close

Send one fixed SendMessage with a fresh <=60s Otto service JWT, then a deliberate
fresh-JWT same-messageId/body/new-RPC-id request. Compare stable result/context and
identityEvaluation metadata. Native proof produces relationship status; private
Kody assertion is profile run provenance only. Do not claim measured exact CLI
invocation count from cached replies alone. Service JWT auth has no jti replay
store; earlier Ed25519 gateway replay401 tests do not apply to this native route.
Stop on unresolved/conflicting decisions or transport ambiguity; no new-event
workaround. No prompt/code/URL/profile/credential inputs are accepted.

The workflow always attempts OFF Worker/config and separate guarded OFF restart,
then requires health/UI/Card404 before removing only the two pilot CF bindings.
It publishes a sanitized OFF receipt. Failed or ambiguous provision is reconciled
by readback while OFF; no secret retry or needless process restart. Unexplained
partial bindings/drift require operator reconciliation, not a bypass.

The custodian must revoke the exact profile token immediately after acceptance,
failure or rollback and verify tokenGet status revoked/active list. Delete only
the newly created GitHub pilot secrets after revocation. The workflow lacks owner
admin credentials and cannot perform token revocation itself; OFF receipt says
revocation confirmation required. CF binding removal does not revoke the token.

Runner loss/cancellation can prevent process cleanup and binding deletion.
The fixed Worker lease independently closes both edge and DO admission of new
Card/A2A requests at now>=deadline, including cached/replayed request paths.
Missing/malformed/overlong leases fail closed; restarting after expiry selects the
ordinary runtime. Already admitted in-flight work can finish within existing
handler timeouts. Token use cannot renew the fixed lease. Lease expiry does not
delete provider bindings or revoke Kody tokens; the custodian must revoke and the
operator must reconcile OFF/cleanup on lost runner. Token absolute expiry also
bounds new private Kody execution. This is not protection against provider clock
compromise, privileged runner compromise or a separate operator changing vars.
Preserve CAS/pending decisions, account data, keys, S3 and Durable Object identity.

Only after accepted live evidence may the separately approved exact identity-test
link.ident.agent/self pointer be written and discovery verified. This workflow
has no account write credential and cannot publish it. Agree exact record value,
perform compare-before-write and retain old value for rollback; no broader schema,
profile, directory, enrollment or Spaces grant is included.

## Local validation versus live proof

Tests use synthetic tokens, simulated providers and injected transport. They prove
sequencing, fixed destinations and guards, not real CF permission, secret API
version semantics, Wrangler rollout-none behavior, live Kody execution or Otto
acceptance. Exact live gates must pass; do not weaken them to make the first run
succeed. No production credential was minted by these tests.

## Requalified baseline after cleanup

At PR25, the initial OFF Worker pin became
`df75d444-fd52-4314-b686-6461b792f4b4` (historical; superseded below). Authenticated read-only inspection
[44921363041](https://github.com/brittanyellich/vlpds/actions/runs/44921363041)
from main `4d2799bba77b2bc4c5099cbd5e8ac01f85220b92` passed with no deletion
attempt. Its single sanitized artifact14712634862 has ZIP SHA256
`3b19afcc31e4e08d3918524f74d6177177f488fe1b2f51bbfe21619bade51919`.
It confirms the qualified current/desired image running, explicit OFF, no lease,
exactly23 binding types, health/UI200 and Card404. Worker script ETag is
`88f6a917a64c75dda70dd40bb76cc74c8607790400fd50349095ec7fe615dc42`;
binding name/type SHA256 is
`0fc25600babf6b573a96519018b704a676c59723f09f83ba89de0b27f3c0c5ad`.
This is historical baseline evidence, not fresh pilot readiness or permission.
The immutable Worker version identifies this exact script/config; the runner
still reads fresh provider metadata and all original preflight gates. Neither
the prior7572 baseline nor provisioned37d6 Worker remains accepted.

This pin update changes no runtime image, Worker source, Card, caller, profile,
credential cap, deadline, rollback or cleanup rule. The native image stays2e254;
Worker qualification stays
`253b25c2baa4983042d803787b60ec0be9838c253b4860761257d0795b345e36`.
Otto's consumer does not pin the initial OFF Worker and needs no code change.
A future approved run must pass its exact new merged main SHA explicitly to
that consumer and authenticate that run's own fresh readiness artifact; prior
heads, inspection receipts and cached readiness cannot authorize a new prompt.
No token, activation or live request is part of preparing this update.

### Historical baseline after run44938309648

The earlier df75 baseline above is historical. Initial pilot pin is now exactly
`05c661c2-dbe6-4131-a1a5-54ced81cad0d`, verified by authenticated GET-only
inspection [44938702703](https://github.com/brittanyellich/vlpds/actions/runs/44938702703)
at approved source3974297. Sanitized artifact14721200224 ZIP SHA256
`c27b9d9e7d19a381d1546f27a842c12076b5c3e26b8d027cd7a3c837b6307a24`
proves OFF/no lease, exact23 binding types and unchanged script88f6..., with the
qualified image2e254 running and health/UI200/Card404. The original7572,
provisioned37d6 and previous clean df75 and23ab Worker IDs are rejected. Qualification
253b25..., native image, caller/Card/credential caps and all other gates remain
unchanged. This immutable baseline update grants no live window or credential
operation; a future run still needs fresh checks and explicit approval. Otto
needs the future exact merged head, with no initial-OFF-pin consumer code change.

### Current baseline and pilot deployment adoption policy

The initial OFF pin is now `8d335d21-6498-43ae-a42d-56c02368782e`, from
authenticated GET-only containment inspection44974048656 after readiness run
44973744829. Artifact14735007003 ZIP SHA256
`f134d5623a8fc59bfbb93dd026c9d25779d0399ed61c6c3087c97dacce83fbe2`
verified OFF/no lease, 23 original binding types (hash0fc256...), unchanged
script88f6..., qualified2e254 desired/current/running and health/UI200/Card404.
The former05c pin and unrelated versions are rejected. This is historical
containment evidence; every future run still requires fresh exact checks.

Pilot ON and OFF publishes share `publishPilotWorker`, which explicitly passes
`--durable-objects-code-update-mode immediate` to pinned Wrangler4.158.0.
It overrides config/default only for those deployments; ordinary deploy and
cleanup commands and the protected config are unchanged. The read-only strategy
projection shares the same constant and reports CLI selection without deploying.
Prior projection44985746171 established default deferred300 at that revision;
it does not prove historical Card failure causality.

Cloudflare applies this strategy to every Durable Object class exported by the
Worker (currently Pds). Immediate adoption resets active objects and may interrupt
in-flight requests, including ordinary PDS traffic. It is not proof that the
container process restarted or received fresh mode/trust configuration: retain
the guarded image restart, signed Card readiness, 600s lease, rollback and
independent OFF/binding verification. OFF publish also uses immediate adoption,
including after failed ON readiness. Ambiguous publish/restart still stops without
retry and requires supported reconciliation; lease expiry alone is not cleanup.

Production use requires explicit approval for one bounded readiness-only window
on the future exact merged head, including Worker-wide ON/OFF resets and possible
request interruption, one scoped temporary candidate and bridge binding, guarded
restart, lease and mandatory OFF/revocation/cleanup. No Otto, discovery, native
image substitution or native race-fix rollout is implied. Git delivery or this
runbook alone does not authorize dispatch, credentials or production changes.

Reference: https://developers.cloudflare.com/durable-objects/deployments/durable-objects-code-updates/
