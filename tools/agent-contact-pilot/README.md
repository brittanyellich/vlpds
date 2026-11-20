# EXP-710 one-agent PDS contact pilot (local only)

This opt-in sidecar implements a stable per-agent Agent Card and authenticated
A2A 1.0 JSON-RPC `SendMessage` route for one read-only skill. A disabled-by-default
native PDS mount forwards only these two fixed routes to the local sidecar.
No existing settings, account data, repository records, or older pilot files
were changed. It was created on `codex/exp-710-agent-pilot` from
fetched `origin/main` at `aa5e87c`. The existing dirty `provider-nov12` worktree
was preserved. Node 26 is required; there are no npm dependencies or CAR parsers.

The fixed identity pair is agent `did:plc:6tlvgafuonoighfrtpejff5m` and principal
`did:plc:exquicw7jew5vxerpgvc3x6w`. These identify the Kody owner's existing local
test, not a new account or permission grant. No enrollment or directory is added.

## Routes and opt-in

At an explicitly chosen `http://127.0.0.1:PORT`:

- GET `/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/.well-known/agent-card.json`
- POST `/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/a2a/v1`

Both require explicit server opt-in (`enabled: true`); otherwise they return404.
The card exposes the one skill, its endpoint, and a required experimental
signature-profile extension. Principal/agent hints are explicitly unverified;
only the skill result distinguishes `verified`, `declared_unverified`, and
`no_declaration`. A hint or result does not authorize other tools. No public
contact record is written. `contactPointer(origin, {optedIn:true})` produces a
local-only draft `{agentCardUrl}`. It deliberately omits an XRPC `contactUrl`,
because this implementation has no XRPC contact binding. Nothing is automatically
mounted or advertised at `pds.crate.social`, atagents.chat, or ident.link.

Input is exact (with a caller-chosen messageId and JSON-RPC id):

```json
{
  "jsonrpc": "2.0",
  "id": "request-1",
  "method": "SendMessage",
  "params": {
    "message": {
      "messageId": "event-1",
      "role": "ROLE_USER",
      "parts": [{"data": {
        "skillId": "resolve-identity-test",
        "agentDid": "did:plc:6tlvgafuonoighfrtpejff5m",
        "principalDid": "did:plc:exquicw7jew5vxerpgvc3x6w"
      }}]
    }
  }
}
```

Only an optional `mediaType: "application/json"` is accepted on that part. No
caller-supplied URLs, prompts, code, tokens, profiles, callback destinations,
task/context IDs, or async configuration are accepted. Event kind is the fixed
skill; messageId is the event ID. The signed request timestamp is the freshness
boundary. This is on-demand contact, not a new PDS repository-change subscription.

## Local sender authentication

The operator supplies 1–8 Ed25519 public-key pins, each identified by sender/keyId.
This is a new local profile; it is not an ATProto service JWT, OAuth, or a feature
of Kody. The route requires `A2A-Version: 1.0` and these signed headers:
`X-Agent-Sender`, `X-Agent-Key-Id`, `X-Agent-Audience`, `X-Agent-Timestamp`,
`X-Agent-Nonce`, and `X-Agent-Signature`. Each must occur exactly once.

The signature is Ed25519 over UTF-8 `JSON.stringify` of this exact array, without
a newline (SHA-256 digest encoded as lowercase hexadecimal):

```text
["atagents/exp-710-local-request",1,sender,keyId,audience,"POST",path,sha256(rawBody),timestamp,nonce]
```

Audience must equal the actual `http://127.0.0.1:PORT` listener origin; path must
equal the complete route, with no query. Timestamp is UTC ISO8601 with milliseconds
and must be within60seconds of wall clock. Signature is canonical padded base64
of64raw bytes. `signedHeaders` is the fixture/operator helper. No caller-provided
key or key URL is accepted. `Host` does not control audience or discovery URLs.
The CLI and socket peer check restrict this slice to IPv4 loopback.

SQLite persists replay nonces and decisions before dispatch. Exact signed-request
replay is rejected. A legitimate same-message retry must be signed with a fresh
nonce and returns the cached outcome without another Kody call; a changed semantic
message under the same ID conflicts. Requests are isolated by authenticated sender.
One process permits one in-flight dispatch. There is no automatic dispatch retry.
A timeout/failure is cached as JSON-RPC `-32603`; a crash leaving `pending` returns
409 on retry and requires operator reconciliation. This provides at-most-once
dispatch attempts, not guaranteed delivery/exactly-once Kody execution. No event
acknowledgment is interpreted as successful identity verification. Limits are
4096request/response bytes, a75second default dispatch timeout, at most1000durable
message IDs per sender, and4096recent nonces per sender. Reaching capacity fails
closed; the operator must reconcile/rotate the disposable ledger explicitly.

## Kody contract

The Kody owner reviewed this seam on November19. Source handoff is the existing
`tools/ident-link-spike/README.md` in the owner's `identity-a2a-local` worktree.
The adapter accepts only one configured `http://127.0.0.1:PORT/a2a/v1` URL and
forwards the exact fixed `SendMessage` schema above. It never forwards caller
authentication, arbitrary fields, raw inbound body, profile, or credentials.
Redirects, oversized responses, transport errors, wrong identities and unknown
statuses fail closed. Unrecognized result fields and raw error/reason strings
are omitted. Responses are immediate messages with a generated contextId that
remains stable on cached retries; this one-shot skill does not accept follow-up
context IDs. There is no task/callback contract. The75second timeout allows the
Kody owner's60second CLI timeout to complete; an overrun still produces a cached
ambiguous failure and requires reconciliation, never an automatic retry. Incoming
HTTP body/header timeouts are separate from the outbound dispatch timeout.

Kody's loopback route currently has **no caller authentication** and no messageId
deduplication. This gateway authenticates its own caller only; it does not claim
end-to-end authenticated Kody transport. Local processes can bypass the gateway
and call Kody directly. The real CLI/profile binding and operator-owned Kody token
remain entirely with the Kody owner. This implementation never reads a Kody token,
launches a CLI, or changes that owner's settings.

The Kody spike's `@atproto/repo` CAR path currently reaches a transitive vulnerable
Zod dependency. No such parser is imported here. Synthetic loopback tests qualify
the adapter; they do not qualify exposing the existing Kody verifier publicly.
Public ingress, parser remediation, production authentication and deployment need
separate work. No inbound Kody webhook is minted or activated.

## Native opt-in mount and local discovery

`src/agent_contact_pilot.rs` and the native server assembly add the explicit
`--agent-contact-pilot http://127.0.0.1:SIDECAR_PORT` flag. It is accepted only with
dev mode, an exact IPv4 loopback `--public-url` and matching `--listen` address.
There is no environment-based auto-enable. With the flag absent no card/contact
routes are mounted. A connection without actual loopback ConnectInfo is denied;
forwarded headers cannot supply it. Only the fixed card GET and A2A POST are
forwarded; there is no dynamic agent, arbitrary upstream, or generic proxy path.

Configure the sidecar's optional `publicOrigin` to the exact native PDS origin
(the CLI config forwards this field). Caller signatures and card URLs then bind
the PDS origin, not the private sidecar port. The native mount verifies the
signed audience header, preserves exact body/authentication headers, rejects
duplicate auth headers and encoded request bodies, and delegates signature,
freshness and durable replay verification to that pinned sidecar. The PDS has
no private signer key or Kody token. No redirects or environment proxies are
used; body/response caps are4096bytes with a5second body-read deadline and an
80second upstream deadline. A mismatched card endpoint fails closed. Neither
the unauthenticated Kody route nor its CAR parser is mounted at the PDS.

`fixtures/link.ident.agent.lexicon.json` is an **unpublished local draft**, with
singleton rkey `self` and only `agentCardUrl`. The matching contact and principal
`link.ident.endorsement` JSON fixtures contain no invitation, token, private
channel, or handler secret. `discoverLocalContact` traverses the exact principal
endorsement URI, its fixed agent DID, `link.ident.agent/self`, then the native
card and fixed A2A endpoint. URLs are pinned to the supplied loopback PDS origin;
alternate singleton keys, identities, private fields and off-origin URLs fail.

These JSON objects are fixture records, not live repository writes or proofs of
ownership/current repository head. Discovery always returns `endorsementVerified:
false` and `authorizationGranted:false`. It does not weaken or replace the Kody
owner's separate signed-endorsement verification. This slice proves lookup and
native routing, not ingestion of a genuine principal repository endorsement.

Independently reproduce the native integration from the repository root:

```sh
cargo build --locked --offline --no-default-features --bin vlpds
cargo test --locked --offline --no-default-features --lib agent_contact_pilot
node tools/agent-contact-pilot/native-smoke.mjs target/debug/vlpds /tmp/exp710-native-result.json
```

The smoke launches actual in-memory native PDS processes sequentially (enabled,
then disabled), a signed sidecar and a synthetic Kody HTTP endpoint on disposable
loopback ports. It tests native card discovery, JSON-only endorsement-to-card
lookup, authentication denial, exact replay401, fresh-nonce cached retry,
one directly counted synthetic dispatch, wrong identity/audience, size limit,
and default-disabled404. It stops owned listeners/processes and removes its
temporary ledger/keys. Memory/ring flags are fixture-specific; no existing user
service or PDS settings are changed. The Kody owner's earlier actual-profile
smoke is separate evidence against the pre-mount sidecar hash, not this native
smoke; its dispatch count was inferred, not independently instrumented.

## Disposable repository-backed discovery

The separate native integration target `tests/agent_contact_repository.rs` uses
actual local PDS `putRecord`, `getRecord` and `deleteRecord` calls against fresh
synthetic principal/agent repos in an in-memory store. It writes
`link.ident.endorsement/<synthetic-agent-DID>` under the principal and
`link.ident.agent/self` with `agentCardUrl` under the agent. No live account,
public schema, persistent PDS config, or existing repo is involved; `validate:false`
marks these unregistered local draft records, without changing the bundled schema.

The test pins public signing keys from that controlled local PDS's `describeRepo`
before the writes. Existing native Rust `common::verify_record_proof` checks
bounded fixture CAR block hashes/CIDs, commit DID/signature and MST record
inclusion or absence. Proof roots must equal `getLatestCommit` before and after
verification, and included values/CIDs must match actual JSON record reads. Wrong
writer/deleter credentials, wrong signer key/DID and tampered CARs are rejected.
This exercises a supported native verifier on controlled fixture data, not the
vulnerable JS/Zod parser and not a public verification endpoint.

Fresh discovery follows the actual principal endorsement read to the actual
agent singleton read and the mounted card. Removing either record stops fresh
lookup; signed non-membership proofs and changed current heads distinguish
deletion from an old still-valid signature. Restoring the pointer recovers lookup
while endorsement removal independently stops it. Pointer removal does not revoke
the card endpoint, previously issued credentials, or existing chat/Space keys.

The synthetic repo DIDs deliberately differ from the fixed Kody test DID. Their
signed pointer can reference its native mounted card, but that **does not prove
the synthetic agent owns the service**. The card remains unsigned and explicitly
claims the separate fixed Kody test identity. The test performs no dispatch and
records `cardOwnershipVerified:false` and `cardSignerVerified:false`. Local
principal endorsement authorship is qualified only against the fixture's pinned
keys/current heads; global PLC trust, key rotation, service-origin ownership,
same-agent signed-card binding and a live pilot are not qualified. Do not turn
successful metadata lookup into an authorization or identity-alias grant.

```sh
VLPDS_EXP710_EVIDENCE_PATH=/tmp/exp710-repository-result.json \
  cargo test --locked --offline --no-default-features --test agent_contact_repository
```

Node26 must be on PATH for the test-only authenticated card fixture
`fixtures/card-server.mjs`. Its ephemeral sender key and ledger remain in memory;
the test terminates that owned child, shuts down the PDS node, and its isolated
test runtime owns and drops the PDS listener. No generated account credentials
are exported in the sanitized optional result JSON. This target can run without
default features; the main suite's unrelated import benchmark requires jemalloc.

## Same-DID signed card acceptance (synthetic only)

`same_did_signed_card_repository_discovery` is the next, separately filtered
native test. It creates new synthetic principal/agent repos, writes and proves
the endorsement and `link.ident.agent/self`, and discovers a signed card whose
advertised DID is the **same synthetic agent DID as the pointer publisher**.
It does not change the fixed Kody identity, existing runtime routes, live DID
documents, or live keys. Its service is a disposable loopback fixture rather
than an actual Kody profile run.

`signed-card.mjs` reuses the Kody owner's **experimental** convention, not an
A2A or ident.link standard: one identity extension
`urn:kody:experimental:a2a-agent-did:v0`, a P-256 key under exact
`DID#card-signing`, and detached ES256 JWS `{protected,signature}`. The protected
header is compact JSON `{alg:"ES256",typ:"JOSE",kid}` encoded as base64url. The
signing input is `protected + "." + base64url(canonical UTF-8 unsigned card)`;
the signature is raw64 IEEE-P1363, not DER. The signer emits low-S signatures.
The verifier rejects unknown protected fields, algorithms, noncanonical base64url,
ambiguous keys/identity extensions, mismatched controller/publisher/DID, and
payload or endpoint changes. It pins one exact loopback card/endpoint origin.

For compatibility, canonicalization first removes nulls, empty strings, arrays
and objects recursively, with nesting bounded to32 and card bytes to8192. This
means empty fields are not protected as distinct raw JSON; consumers receive
only the verified normalized view. In particular, empty security-scope objects
can disappear under this experimental convention. The synthetic endpoint uses
a required nonempty authentication extension and a separate private disposable
bearer token, not an empty standard security-requirements object. A production
signature/authentication profile must resolve these normalization semantics.

The trusted synthetic `#card-signing` document arrives through the operator-owned
child process pipe **before HTTP discovery**, independently of the fetched card.
Its public key must agree with the card signature and synthetic publisher DID.
This is an explicitly trusted fixture binding, not a card-supplied key, global
PLC resolution, or an update to the PDS account's real DID document. Repo signing
keys remain separate from the disposable P-256 card key. The native verifier
independently checks the principal/agent repository proofs and current heads;
the card verifier does not infer those proofs or authorization from a signature.

```sh
VLPDS_EXP710_SIGNED_EVIDENCE_PATH=/tmp/exp710-signed-card-result.json \
  cargo test --locked --offline --no-default-features --test agent_contact_repository \
  same_did_signed_card_repository_discovery
```

The test rejects publisher, claimed DID, singleton and trusted-key substitutions,
changed card content, and a changed endpoint even when the expected path is
changed too (the signature must still fail). It exercises the synthetic A2A route:
no token gives401; the private fixture token permits only a fixed read-only
synthetic pair and returns `declared_unverified`. No token/private key is exported.
The optional result contains public trust pins, signed card, and synthetic repo
proofs. The child is terminated and waited; the PDS uses only in-memory state.

`signed-card.test.mjs` also has an optional offline interoperability test using
explicit `KODY_CANONICALIZE_MODULE` and `KODY_CRYPTO_MODULE` filesystem paths to
the owner's safe `canonicalize` and `@atproto/crypto` entry points. It checks
canonical payload equality, Multikey agreement, and Node↔ATProto ES256 signatures
in both directions. It never imports Kody `card.mjs`/`verify.mjs` or their CAR path.
Without those optional paths, the crosscheck is explicitly skipped, not passed.

This proves signed same-DID contact discovery **relative to independent fixture
pins**, with signature coverage of the advertised endpoint. It does not qualify
HTTPS certificates/host routing, real origin control, global DID/key authority,
rotation/revocation, signed-card freshness/cache/rollback policy, production
caller authentication, real Kody/runtime health, public CAR safety, or live
publication. Those remain explicit gates before a live pilot; signature validity
does not grant tasks, account control, Space membership or encrypted keys.

## Fixed-DID resolver and observed key lifecycle policy

`card-resolver.mjs` is an internal readiness prototype, not a new public route.
It reads only the fixed configured Kody test DID from one operator-selected
HTTPS origin (default `https://plc.directory`), with a constructed fixed path.
Requests cannot choose another DID, origin, key URL or trusted key. DID services,
card fields and JOSE hints cannot redirect resolution. Native HTTPS certificate
and hostname verification remain enabled, no redirects or environment proxies
are used, and only JSON200 responses are accepted with a32KiB cap and3second
total deadline. Tests use normal TLS against a private synthetic CA scoped only
to that client; they do not query public metadata or change system trust.

Only the exact controlled `DID#card-signing` P-256 Multikey is selected. Snapshots
have a5second maximum monotonic TTL; fetches coalesce and have a1second default
cooldown. Callers cannot force bad-signature refreshes. Expiry, TLS/transport
failure, redirects, oversized/malformed data, identity/controller mismatch or
missing keys fail closed with no stale fallback. A card accepted before a key
change can remain acceptable within the configured TTL; this bounded window is
intentional. Operator-side `invalidate()` drops cache and in-flight results; it
is not exposed to public request data. Verification rechecks generation/expiry
before returning. Close the resolver before closing its journal.

`openCardKeyJournal(ownerChosenPath)` records only public-key fingerprints and a
monotonic local generation for this fixed DID and authority origin. A newly
observed valid key retires the preceding key. Explicit same-DID deactivation/key
removal or authoritative404/410 retires the current key. Retired keys cannot
reactivate automatically, including after restart; an unobserved fresh key can
recover from revocation. Transient outages do not permanently retire a key, but
verification remains unavailable until a fresh valid read. At most64observed
keys are retained; exhaustion fails closed. Generation checks prevent an older
in-flight read from overwriting or revoking a newer journal state. The journal
has no reset/reactivation API: intentional key reuse, origin migration, history
compaction or disaster recovery requires an independently reviewed operator
procedure. The caller must keep this trust state owner-controlled and durable
for hosted use; tests use only disposable SQLite in private temp directories.

This policy trusts the operator-chosen HTTPS resolver's current representation;
it **does not verify PLC operation-log signatures/lineage**. The journal prevents
rollback to keys this installation has already retired, not an unobserved
history, a malicious trusted authority, pre-observation rollback, lost/restored
journal state or globally coordinated freshness. It adds no production caller
auth, HTTPS card/dispatcher binding or service-readiness proof. Actual live
`#card-signing` availability is unqualified: all test documents are synthetic.

The resolver's `verify` supplies its own trusted document to the local card
verifier. It never parses CARs, resolves endorsements, follows PDS services,
fetches arbitrary cards, or invokes Kody. Keep public contact input out of Kody's
vulnerable CAR-backed verifier until that dependency/parser path is qualified.
Before hosted ingress, separately establish HTTPS origins/certificates, a
reviewed card/freshness profile, production caller authentication, authenticated
gateway-to-dispatcher transport (the existing Kody loopback endpoint has none),
profile-bound least-privilege execution, and explicit account/record approvals.

`card-resolver.test.mjs` exercises real local TLS, a fixed path, coalescing,
rotation/revocation/rollback across restart, cache windows, outage/size/redirect
denial, deadlines/cooldown, caller-key rejection and in-flight invalidation.
The CI `Local agent contact pilot` job installs Node26, runs these dependency-free
tests and native acceptance sequentially. The optional cross-worktree Kody crypto
interop check is skipped in ordinary CI and was run explicitly locally.

## Run and validation

```sh
cd tools/agent-contact-pilot
npm test
npm run check
node run.mjs /absolute/path/to/owner-only-local-config.json
```

An operator-created config (mode0600) must set `enabled:true`, a port1024–65535,
an absolute disposable SQLite `database` path, `kodyEndpoint` as above, and
`senders:[{sender,keyId,publicKeyPem}]`. With a native mount, also set `publicOrigin`
to that PDS's exact loopback origin. There are no example credentials, generated
account keys, implicit environment lookups, or default enabled service. Only
fixture-generated ephemeral keys are used by tests. Stop with SIGINT/SIGTERM;
the operator retains the durable ledger for ambiguous-outcome reconciliation.

The focused tests exercise real loopback HTTP and SQLite restart behavior with
synthetic Kody responses. They cover fixed discovery, opt-in pointers, destination
and body-bound signatures, freshness, sender/key substitution, nonce replay,
durable request deduplication, pending-state recovery, single concurrency,
sanitized cached failures, redirect/timeout/size denial, malformed input, and
fixed dispatch. No real account write, public identity fetch, credential change,
profile run, PDS configuration change, or public publication occurs in these tests.
The previous provider/Spaces integration evidence is separate and is not claimed
as testing this branch or this contact adapter.
