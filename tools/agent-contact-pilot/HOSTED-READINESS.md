# EXP-710 hosted preparation — historical design

Brittany redirected the standalone/Fly proposal to native vlPDS. No Fly resource
was created. Current implementation and approval gates: [NATIVE-ROLLOUT.md](NATIVE-ROLLOUT.md).
The analysis below records earlier preparation; do not use it to launch a service.

Baseline: merged commit `207de7b67c28066472d0a8384da3a6e1df3a6a45`.
Local branch: `codex/exp-710-hosted-readiness`; no commits/pushes.

## Smallest stage

A separate approved staging HTTPS hostname under atagents.chat, one fixed DID
`did:plc:6tlvgafuonoighfrtpejff5m`, one authorized caller public-key pin and its
own durable replay ledger. Expose only a stable per-agent card GET and fixed-skill
signed A2A POST. Preserve the exact public HTTPS audience/path end to end; never
rewrite a signature to a loopback audience. Add connection/rate bounds alongside
existing byte/deadline/ID bounds. No ident.link publication or reservation.

This is a design, not an executable deployment artifact. The merged native mount
requires dev mode and matching HTTP IPv4 loopback public URL/listener. Sidecar,
pointer and signed-card verifier also require loopback. Preserve those guards;
do not enable dev mode or change the deployed PDS URL. Implement a separately
reviewed explicit HTTPS-origin mode and synthetic TLS ingress harness first.
Cloudflare routing rejects percent-encoded paths, including the pilot DID path:
do not relax its global rule; future integration needs an exact isolated route
and encoding tests. The Dockerfile packages Rust/UI, not Node/sidecar. Prefer an
independently pinned staging sidecar artifact with existing PDS untouched.

## Identity evidence and gaps

Read-only PLC metadata at 2026-11-20T04:47:26Z returned200, DID JSON media type,
and exact #card-signing, #atproto and #atproto_kem methods for the fixed DID.
The merged resolver rejected `application/did+ld+json; charset=utf-8`; the local
fix accepts that specific media type plus application/json, retaining normal
TLS, byte/time limits and fail-closed behavior. No live keys loaded or changed.
This is metadata availability, not key possession or endorsement verification.

Use the fixed HTTPS authority and observed-key journal (maximum5s cache, no stale
fallback, retired-key rollback rejection). This trusts authority TLS, not PLC
operation-log lineage. Identity owner must approve the exact endpoint and provide
a signed card through an owner-controlled signer; independently verify publisher
DID/current card key/endpoint signature. Do not substitute #atproto or copy private
keys here. Card freshness/recovery needs agreement. Publishing link.ident.agent/self
is separate opt-in; pointer deletion does not revoke endpoint or keys.

## Dispatch and vulnerable proof boundary

Kody owner's read-only review confirms current loopback /a2a/v1 has neither caller
auth nor deduplication. It must remain private. Current hosted HMAC webhook
conventions are not the Ed25519 gateway profile; no webhook/token is minted here.
Use an authenticated private dispatcher with exact fixed pair/skill, server-owned
profile/token and event payload binding. A reviewed private signed envelope or
mutual TLS must bind peer/audience/method/hash/expiry/event ID. Reserve durable
idempotency before dispatch; cache ambiguous failure and reconcile without retry.
No caller URL/profile/token/code is forwarded. Unauthenticated localhost TCP does
not prove dispatcher peer identity.

Do not connect public requests to existing JS verifyAgent/proof.mjs. Kody owner
reports @atproto/repo0.11.5 -> Zod3.25.76, no compatible audit fix, and up to4MiB
CAR parsing. Fixed caller inputs do not qualify remote repository bytes. Candidate
replacement: local bounded Rust proof adapter, described in RUST-PROOF-GATE.md;
not integrated into any hosted dispatcher.
The existing public `src/oauth/lexicon.rs` verifier still enforces
com.atproto.lexicon.schema, so is not a drop-in
endorsement verifier. Adaptation must fix path/type/pair, resolve current repo
signing key, check CID hashes, commit DID/signature, MST inclusion, record CID/value,
and current head before/after, with strict origins/size/time and malformed/stale/
absent/wrong-key tests. Existing synthetic repository proofs do not qualify the
live JS path. Hosted real dispatch is blocked until safe proof replacement passes.

## Approval packet and rollback

Local synthetic work may continue. Before commits/push/PR for this new slice obtain
fresh authorization. Before staging Brittany must approve exact hostname/project,
resource budget, artifact digest, ingress and caller pin. Identity owner separately
approves card signing/endpoint and any repo pointer publication. Kody owner approves
private dispatcher artifact/profile/server-held credentials and proof replacement.
Enrollment/directory/Space grants remain later. No live settings/credentials/deploy
or records are authorized by this preparation request.

Deployment packet must pin source revision, image SHA256/digest, runtime/dependency
inventory, effective config with secret paths only, DNS/TLS ownership, card digest,
sender pin, authentication profile, safe-proof qualification, tests and rollback.
No hosted image was built and no digest is claimed; there is no deployable hosted
artifact yet. Merged baseline and uncommitted compatibility fix are distinct.

Proposed rollback: disable only exact staging ingress first, stop owned staging
sidecar/dispatcher, retain private ledger for ambiguous-call reconciliation, revoke
only separately issued staging credentials with owners. Any public pointer removal
needs separate approved repo write; DNS removal alone is insufficient revocation.
PDS image/config/account data and existing Kody profile stay untouched. Local rollback
restores only this branch's tracked diff after preserving evidence, never unrelated
checkout changes. All local TLS fixture keys/listeners are temporary and cleaned.

Brittany subsequently authorized isolated staging deployment once gates pass,
but excluded credential/settings changes, spending and commits/pushes. This does
not authorize tokenCreate, webhook mint/publish or production PDS mutation. Kody
owner found no existing approved authenticated hosted dispatcher/profile token.
That concrete credential/endpoint approval remains required for real rollout.
