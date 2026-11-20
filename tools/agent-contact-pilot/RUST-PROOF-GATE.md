# Bounded Rust fixed-pair endorsement gate

Current integration is documented in [NATIVE-ROLLOUT.md](NATIVE-ROLLOUT.md): the
network-free core below is now called by a separate fixed-origin native fetcher
and default-off authenticated native route. Private request-only hop discussion
below is historical prototype evidence; production candidate uses mutual HMAC
request/response authentication. No production deployment/profile token is active.

Local prototype `src/agent_endorsement.rs`; no HTTP route, subprocess or dispatcher
is wired to it. No JS/Zod/@atproto/repo import is in this proof execution path.
Existing Kody real-profile code STILL uses its JS parser: the hosted path has not
been replaced, so this gate alone does not make that service safe to expose.

`verify(&TrustedSnapshot, car, fetched_record)` accepts only the fixed Kody agent
and principal pair. TrustedSnapshot carries independently obtained DID documents
and current head reads before/after proof acquisition. These are internal trust
inputs, NEVER fields copied from a public request, card or CAR. No network fetch
or authority authentication is implemented here. Document trust, freshness,
origin allowlist and total fetch/CPU deadline remain the future transport layer's
responsibility; equal supplied heads cannot prove a dishonest PDS told the truth,
prevent ABA changes, or guarantee no mutation after the check.

It checks the exact agent alsoKnownAs declaration of the principal, exact principal
#atproto Multikey/controller with no duplicate key IDs, and rejects deactivated
metadata. Reciprocal evidence is agent DID declaration plus principal repo record;
there is no assumption that principal alsoKnownAs must declare the agent. This is
relationship verification relative to the supplied trust anchors, not caller auth,
card ownership, task authority, account control or Space/key permission.

The shared native inclusion primitive was factored from oauth/lexicon.rs. Its
existing public lexicon verifier still enforces com.atproto.lexicon.schema; only
the new adapter applies endorsement semantics instead. Native CAR block hashes,
commit DID/signature (low-S Multikey), MST path inclusion and record bytes are
verified. Adapter enforces64KiB input,64 unique blocks,16KiB/block, one pinned
root,32KiB/doc,128 aliases/methods,4KiB fetched JSON, fixed URI/type/agent and exact
CID/value equality. Extra endorsement fields deliberately fail this minimal slice.
Native CBOR depth limit is128; the adapter has no hard wall-clock CPU preemption.
Byte/block bounds cap the supplied input, not a formal worst-case CPU proof.

Only a valid signed non-membership proof with no conflicting JSON read returns
Outcome::Absent. Missing/malformed proofs, wrong key/head/value and transport errors
must not be collapsed into absence. The future fetch layer must distinguish a
getRecord404 from transport/authority failure, acquire and verify absence proof,
and must not treat network404 alone as authenticated revocation.

Disposable Rust fixtures generate fresh secp256k1 keys, canonical CBOR signed
commits and native MST/CAR blocks in memory. They deliberately label synthetic
commits with the fixed pair solely to test pinned-key mechanics. They do NOT use
or prove possession of live fixed-DID keys or modify live repositories. Tests
cover inclusion, signed absence, reciprocal removal, wrong signer/controller/DID,
wrong path/CID/URI/value, changed/stale heads, tamper, duplicate/too many blocks,
oversized input and every truncated prefix of a valid fixture. No Node process,
network listener, profile credential or persistent test key is needed.

Reproduce from repository root:

```
cargo test --locked --offline --no-default-features --lib agent_endorsement
cargo test --locked --offline --no-default-features --lib oauth::lexicon
cargo test --locked --offline --no-default-features --test agent_contact_repository -- --test-threads=1
cargo clippy --locked --offline --all-targets -- -D warnings
```

The repository-backed integration target separately uses real disposable in-memory
PDS account writes/reads/removals under synthetic DIDs. It is not evidence of the
fixed live pair. No global PLC log proof, network race qualification, hosted HTTPS,
actual Kody integration or production deployment is claimed by either fixture.

Kody owner confirmed the contract read-only, including exact ident.link declaration
URL (existing identity convention, not a new namespace reservation/publication).
No existing approved hosted authenticated dispatcher/token is available. A real
profile bridge needs explicit approval for its private authenticated host/endpoint
and profile credential lifecycle; a deterministic dispatcher must not be deployed
or described as the real profile. No commits/pushes or live settings/credentials
were changed by this gate.

## Kody read-only interface review

Kody owner confirmed core semantics for source SHA256
`df171614266ee5210efa5395c01857c894f447de323bf814f63e0dc9c58f3eed`.
Strict minimal fields, controlled key, one root and proof-qualified absence are
stronger local requirements, not exact JS acceptance equivalence. A future A2A
adapter must classify no_declaration only after successful trusted agent DID
fetch with no target alias, BEFORE invoking this verifier. Never map arbitrary
Err to no_declaration. Verified maps to verified; signed Absent with a valid
agent declaration may map to declared_unverified with an absence reason. Key,
head, transport or malformed-proof errors remain lookup failures, not proof of
absence. No such status-mapping network adapter is implemented in this slice.

## Private authenticated hop prototype

`private-dispatch.mjs` constructs a new signed fixed request with a separately
pinned private sender identity and an exact configured loopback destination.
It is tested against createPilot's signature/freshness/replay checks and a
SEPARATE durable-decision ledger. It does not forward public caller credentials.
A fresh-nonce same-event retry returns cached output; an independently counted
synthetic dispatcher executes once. Wrong key/unsigned request, wrong endpoint,
wrong RPC correlation and oversized response fail closed. No automatic retry.
This is private-hop mechanics only: the injected result is synthetic, not a Rust
subprocess result or real Kody profile invocation. A real authenticated native
result channel and profile assertion-only module remain to wire/review.

Brittany subsequently approved a private authenticated dispatcher and an
identity-test-scoped credential, but mint/store only AFTER destination selection
through its approved secret mechanism. No destination is established by local
config: assigned Cloudflare crate-pds is the production PDS Worker/Container,
not an isolated Node/Rust runtime, and Kody CLI cannot execute inside a Worker.
No token was minted, credentials stored, DNS changed or paid resource created.
Staging deployment approval does not imply those unrelated mutations. Recommend
an existing approved isolated Node/Rust-capable host and HTTPS endpoint first;
a2a-pilot.atagents.chat remains the proposed eventual hostname pending DNS approval.

The local private-hop signature authenticates the request sender to the receiver.
It does not authenticate the HTTP server's response or establish mutual TLS.
Do not describe loopback as a server credential. Exact process-owned listener
and ephemeral fixture custody are test assumptions. A hosted private hop still
needs normal HTTPS with pinned destination identity or a separately reviewed
signed response/mutual TLS channel before a Rust/profile result is trusted.
