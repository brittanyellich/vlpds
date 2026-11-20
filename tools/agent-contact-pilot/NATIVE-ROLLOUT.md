# EXP-710 native PDS opt-in — local candidate, not deployed

Brittany redirected this work from standalone Fly staging into vlPDS. No Fly
app/Machine/volume was created; Fly login is unnecessary. No production settings,
DNS, live records or credentials have changed. This follow-up is on
codex/exp-710-hosted-readiness, based on merged207de7b. Commit/push/PR was
separately authorized on November 20; deployment remains unapproved.

## Native boundary

A new --agent-a2a-config / VLPDS_AGENT_A2A_CONFIG owner-only file enables ONLY
one fixed DID's card and A2A SendMessage routes on the existing PDS. It is absent
by default and mutually exclusive with the old dev-only sidecar mount. Production
requires the exact public HTTPS origin; loopback HTTP is allowed only in dev mode.
No automatically published pointer, generic executor, directory or signup exists.
Production requires a signed Card file plus an independent public key pin. The
native gate verifies ES256/raw64 over JCS bytes of the exact v1 ProtoJSON template,
preserving the empty security requirement map entry. Legacy recursive empty-value
removal is incompatible. The advertised DID, publisher DID, key controller and
DID#card-signing must agree; the endpoint and audience are signed. No private
Card key is loaded. Current fixed-origin DID resolution is bounded, cached for at
most five seconds, and fails closed. Observed key removal/change permanently
retires that configured pin in private CAS history; rotation requires a new
operator-approved Card/pin. Retaining that history is required across rollback.

Disposable same-production-DID vectors passed native verification, independent
Node ES256/JCS checks, canonicalize@2.1.0 byte comparison, and the official Go
SDK v2.5.0 ProtoJSON parser. A synthetic key was rejected against the live public
DID key, and its retirement survived a disposable PDS reopen. These checks use
no live signing key and do not establish ownership of one. Release remains
blocked until the owner signs the exact frozen template with the existing
published key and the resulting public artifact passes this gate.

Exact recipient: did:plc:6tlvgafuonoighfrtpejff5m.
Exact principal: did:plc:exquicw7jew5vxerpgvc3x6w.
Intended first caller Otto: did:plc:vsgwub3c3pupqt3yhxfmecma,
handle otto.brittanyellich.com (coordinator verified DNS TXT + DID alsoKnownAs).
No Otto files/settings were read or changed here. Its ability to issue this
service token remains a caller-owner acceptance gate.

At the existing configured public origin:
GET /agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/.well-known/agent-card.json
POST /agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/a2a/v1

POST requires A2A-Version:1.0, unencoded application/json, <=4096bytes, one
Authorization:Bearer service JWT. Existing native issuer DID/key verification is
reused with exact configured caller allowlist BEFORE key lookup, exact PDS audience
and method binding. Public PDS metadata currently returns service DID
`did:web:pds.crate.social`: that is the intended aud; lxm must be exactly
`chat.atagents.agent.contact`. typ JWT/alg ES256K or ES256, integer iat/exp,
0 < exp-iat <=60seconds, <=60second age, <=5second future iat,
<=65second remaining lifetime, and any nbf
must already be valid. This is service delegation, not a new OAuth/session token
or proof that an endorsement authorizes tools. Normal service-token validity/cache
windows apply. Never take a caller DID or key from message JSON or a card.

The only body is the existing fixed skill/pair schema in README.md; messageId
is a caller-chosen bounded event ID. No task/context/URL/code/token/profile input.
This remains one-shot identity resolution, not a chat follow-up/Spaces endpoint.

## Durable execution and proof

Private rows use the existing owner-routed conditional-write log under the
recipient DID, with versioned agent-a2a/v1 prefixes. One transaction reserves the
caller+messageId row, canonical fixed-request digest, a global recipient inflight
slot and an operator-configured bounded event count (default1000, maximum100000). Fresh requests cannot pass a held slot.
Same authenticated caller+ID/digest returns the stored stable message/context;
changed digest conflicts and another caller cannot read the cached decision.
No model/profile call happens before reservation. Native routes use the existing
global IP limiter before authentication. Completed replies include immutable
identityEvaluation metadata (evaluation Unix time and observed CIDs), preserved
on cached retry; a cached verified result is historical, not a renewed check or
an authorization grant. There is no automatic retry of
a timeout/crash; pending/inflight stays blocked if the future is cancelled before
committing a decision. Operators must reconcile rather than delete pending rows
and blindly retry. The bounded event store has no automatic eviction/reset. Quota exhaustion returns
terminal429 DecisionCapacityReached. Raising decision_capacity within the bound
allows new events without erasing cached/pending decisions; the native fixture
tests this recovery. Never remove the count or delete decisions to gain space.

Cluster forwarding sends only the two exact native paths to the configured
recipient's shard owner; public input cannot select that key. Private CAS remains
owner serialized across nodes. Full multi-node ownership-move acceptance is not
yet qualified by the current single-node tests.

The Rust resolver constructs only fixed PLC and pds.crate.social HTTPS URLs,
uses the native public-IP DNS guard/no proxies/no redirects, bounds bodies and
per-request/overall deadlines, checks current agent/principal DID documents,
PDS service pins, principal current heads, signed native CAR/MST and matching
record CID/value. It refetches DID documents to detect observed key/declaration
changes. Migration requires explicit endpoint review. Authority TLS and observed
head equality do not prove PLC log lineage, prevent ABA/later mutation or provide
an independently signed global freshness oracle. See RUST-PROOF-GATE.md.

Read-only public interoperability succeeded for the real fixed pair, with no
credential/profile invocation. Synthetic fixtures still cover tamper, wrong key,
record/head/pair/path, absence, truncation and limits. This is separate evidence
from Otto-to-native contact or actual Kody dispatch, which have not happened.

## Private profile bridge and packaging

Rust performs relationship verification; the private Node bridge performs only a
fixed identity-test profile assertion. It never imports JS verifyAgent/proof.mjs
or @atproto/repo CAR parsing, never accepts caller code/module/profile/token/URL,
and returns no proof status. Native Rust alone determines status. HMAC-SHA256
request and response profiles bind domain, method, exact private path, boot epoch,
timestamp, nonce and request/response hash; event ID/pair/skill are in the hashed
body. Challenge MAC authenticates the boot epoch, nonce tracking rejects within-
boot replay and a new boot rejects captured old requests. A dedicated32byte key
is independent of the Kody token; loopback is not treated as authentication.
Native durable reservation prevents legitimate redispatch after process restart.

Kody owner supplied reviewed adjacent assertion/production-adapter modules. The
adapter uses only the preinstalled pinned CLI3.46.2, checks its manifest/path,
restricts child env to PATH/HOME/KODY_API_TOKEN, has a60second timeout and hides
CLI errors. No npx/npm resolution occurs at runtime. Package lock, module hashes,
CLI, platform esbuild and workerd1.20260815.1 are baked at build; workerd archive
checksums are pinned per architecture. Kody API network is still required for its
runtime package graph and metaGetCurrentUser. No profile token is currently minted
or stored by this candidate.

`docker build --target agent-a2a -t <local-candidate> .` selects the explicit
optional artifact. Default Docker final target remains the existing Rust/UI
image and entrypoint. The opt-in artifact contains a supervisor which starts the
bridge only when VLPDS_AGENT_A2A_ENABLED=true AND the exact Otto caller plus
separately supplied bridge-key/profile-token secrets are present. It materializes
owner-only ephemeral files and removes those secret env values before native
PDS/bridge children; CLI child receives only its token. /opt runtime is owned by
root, executed by the non-root PDS user, /tmp remains writable. No keys/tokens are
baked in image or passed as command arguments.

## Cloudflare and approval/rollback

Worker AGENT_A2A_ENABLED defaults absent/off. Only when explicitly enabled do the
two exact uppercase-encoded fixed-DID paths bypass the global percent-encoding
rejection, on PUBLIC_HOST with no query. Alternate casing, double encoding,
other identities, suffixes and wildcard hosts still fail closed. The Worker flag
alone does not enable native routes; native config is separately required. No
Worker vars/secrets/routes or deployed image have been changed. The optional wrangler.agent-a2a.jsonc selects Docker build_vars
VLPDS_RUNTIME_STAGE=agent-a2a and a native-profile-v1 capability marker; enabling
the flag with the ordinary config is refused before container startup. The native
entrypoint/env are selected together, with explicit Otto/key/token checks. Full
optional-artifact acceptance must still be validated before rollout;
source code alone is not live readiness.

Before approval: finish local runtime supervision/negative tests, full optional
PDS image/default-off smoke, complete Roast findings, native fixed-pair HTTP +
real profile acceptance without exposing JS proof, and confirm Otto's existing
service-JWT capability. Obtain the owner-signed exact native Card artifact and
verify its current public key pin; unsigned production Cards are refused.
Then review exact image digest/source manifest, required existing-project secret
names and scopes/expiry, environment flags, recipient/caller, rollback and budget
(no Fly service). Only after explicit exact-plan approval may production settings
or deployment change. The November 20 authorization permits this follow-up commit/push/PR, not deployment.

Rollback plan: disable Worker exact-route flag first, disable native config/agent
supervisor, restore the prior pinned PDS image/entrypoint without changing account
storage, retain private decision rows/pending markers for reconciliation. Revoke
only any newly issued profile token and dedicated bridge credential with their
owners. Do not remove public records (none are published here), reset accounts,
erase CAS history or reuse a spent/ambiguous event with a new ID as an automatic
recovery action. A temporary fixed-auth test is not a general tool grant.

## Protocol pin and independent profile evidence

Wire reference: [official A2A1.0.0 specification](https://a2a-protocol.org/v1.0.0/specification/).
The narrow JSON-RPC binding uses SendMessage, ROLE_USER/ROLE_AGENT and unified data
parts. Version refusal uses -32009 with typed google.rpc.ErrorInfo; invalid request,
unknown method and invalid params remain distinct and correlated. It does not claim
full task/stream/push interoperability; those capabilities are not advertised.

Kody owner independently ran the exact Linux profile image
sha256:b3941c0bb473abea47b9f37f8a29026394aee28746dc54e55c1564fc12d7a427
through the owner-run stdin-to-tmpfs harness. A short-lived org:execute token
asserted the fixed profile; HMAC challenge/response, unsigned denial and replay
denial passed. Token/key were absent from Docker metadata, no host port was
published, container/tmpfs and owner temporary files were removed; tokenGet showed
revoked and active tokenList empty. One successful assertion was observed; exact
CLI invocation count was not independently instrumented. This is profile-path
acceptance on that immutable image, not native public HTTP or Otto acceptance.
The final native candidate will record its own digest and component hashes.
