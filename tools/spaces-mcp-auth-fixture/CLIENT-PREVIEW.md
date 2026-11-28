# Isolated Muse and Duet preview

## Rehearse locally

Run the following from a checkout that includes the verified PDS owner-session fixture.

```sh
export EXP711_WORKERD=/absolute/path/to/workerd
export EXP711_OAUTH_PROVIDER=/absolute/path/to/oauth-provider.js
sh tools/spaces-mcp-auth-fixture/validate-preview.sh
```

Use workerd 2026-11-17, the bundle from `@cloudflare/workers-oauth-provider` 1.2.1, and the locked Rust dependencies. The runner requires the Worker-specific pass markers. It starts only disposable IPv4 loopback listeners and removes the package and test state on normal exit. Each run allocates a fresh port. The signed flow requires OpenSSL and uses `https://127.0.0.1:<allocated-port>` as its issuer with a disposable certificate trusted only by the reference client. Its issuer pins discovery, consent, and signed dispatch to the same origin. The unsigned fixture still uses HTTP. For both flows the issuer is the listener origin, its resource is that origin plus `/mcp`, and its reference callback is that origin plus `/callback`. The package gives each run a private issuer database in its disposable directory. The signed test keeps the same Worker-issued grant across Worker and PDS restarts. A stable loopback listener forwards signed dispatch to the replacement PDS, which opens the sealed scoped credential, persists each refresh rotation, and reads the existing conversation. The test retries a prior send and then revokes the grant. The command is an automated qualification harness. It does not keep an endpoint running for interactive clients.

## Pin the hosted preview

Use an approved nonproduction HTTPS origin. The following values use the reserved example domain and describe the exact URL relationships. Substitute one approved real hostname consistently before creating clients or grants.

| Setting | Preview value |
| --- | --- |
| OAuth issuer | `https://mcp-preview.example.invalid` |
| MCP resource and token audience | `https://mcp-preview.example.invalid/mcp` |
| Authorization-server metadata | `https://mcp-preview.example.invalid/.well-known/oauth-authorization-server` |
| Protected-resource metadata for `/mcp` | `https://mcp-preview.example.invalid/.well-known/oauth-protected-resource/mcp` |
| Registration | Discover the issuer's `registration_endpoint` if that client supports dynamic registration. Otherwise use the client’s supported registration method. |
| Client callback | Record and verify the actual client's complete redirect URI before registering it. The local fixture callback has no relationship to a native client callback. |
| Private PDS dispatch | `POST /xrpc/vlpds.agent.dispatch` at the isolated PDS, with the pinned preview signer, issuer and resource. |

Owner sign-in and consent must happen on the isolated service. The signed Worker calls the disposable PDS sign-in endpoint through a private service binding. Sign-in leads to a separate approval page displaying the verified owner, agent and Space. Approval is one-time and the PDS checks that the reviewed binding still matches. Keep the loopback fixture loopback-only. Short-lived browser state is shared across Worker isolates in a dedicated Durable Object instance. Bind each authorization request to a verified full PDS session, show the verified owner and exact approved Space, and require explicit approval. Follow the durable issuance sequence of reserve, claim, issuer completion, PDS binding, then redirect. Verify both sides of ident.link for two disposable owner–agent pairs. Give the server provider refreshable AT Protocol OAuth credentials with DPoP and exact Space scopes. Keep provider state, key material, and Space records separate from production. The current Worker/PDS harness qualifies the authentication and dispatch boundaries locally. The isolated PDS process and managed credential provider still need wiring.

## Validate actual clients and clean up

1. Record each client's build, transport requirements, registration method, and exact callback URI. Check that it can reach the isolated origin and supports Streamable HTTP JSON and browser OAuth with S256 PKCE. Stop at the first unsupported or unverified step.
2. Connect Muse as owner A and Duet as owner B, or run one available client first. Verify resource discovery, consent, callback, token exchange, MCP initialization, and tool discovery. Use the same MCP endpoint for both owners and distinct browser sessions.
3. Start a chat, send synthetic text, retry the same message ID, and read history. Expect equal receipts and one record per owner under the correct author DID. Reconnect and read that history again. Try the other owner's conversation ID and expect denial for send and history.
4. Revoke owner A's grant. Confirm the old token and refresh fail, the denied send creates no record, and owner B can still chat. Keep the agent identities intact during this check.
5. Revoke both preview grants and verify issuer and upstream cleanup. Remove disposable client registrations, credentials, signer material, and test storage under the approved teardown scope. Shut down the preview. Record only redacted outcomes and client/version information.

A hosted run requires explicit approval for the chosen nonproduction origin and environment, disposable account and key issuance, and test data cleanup. No production deployment workflow is part of this runbook.

The private recovery API is mounted on a separate router at `/internal/agent-grant-recovery`. The disposable listener forwards to that router on the current PDS app, including after restart. The API requires both the service token and a verified owner session. The public PDS router leaves the path unavailable. A hosted preview still needs a private listener and service binding, an owner-to-Space binding lookup, preview-only durable issuer and PDS storage, and a recovery runner that retries issuer and upstream cleanup. Use a managed wrapping key and a durable single-writer or compare-and-swap protocol for refresh rotation. If an issuer rotates a refresh token before the new envelope commits, the provider needs issuer-supported recovery or a fresh owner authorization path.

## Hosted credential recovery

The mounted disposable provider stores sealed credentials in the owner's private PDS partition. It uses a compare-and-swap keyed by the exact agent and Space binding to replace the usable envelope with a unique rotation claim before calling the issuer. Only the claim winner can refresh, and only that claim can commit its replacement. An unresolved claim survives restart and blocks reuse of the previous envelope. The separate file-based crash fixture exercises an issuer-accepted refresh with no saved replacement and verifies that fresh owner consent can recover the same Space record.

Before hosting, configure a dedicated Worker at the approved preview origin, a stable private PDS service binding, and independent issuer, PDS, and Space storage. Give the session provider a dedicated managed wrapping key and restrict unwrap access to its service identity.

The local re-consent transaction compares the blocked generation and atomically writes the replacement envelope and exact old-grant retirement record. A delayed response to the old refresh cannot replace the new envelope. Cleanup retries use the stored owner, issuer, client, and immutable upstream grant ID. If the issuer cannot independently confirm the old grant's identity or retirement, keep cleanup pending for reconciliation. The hosted consent verifier, cleanup scheduler, and issuer adapter still need wiring.

## First hosted smoke test

1. Provision a preview-only Worker, private PDS, issuer and Space stores, and a managed wrapping key. Give the Worker a private binding to the PDS consent, recovery and signed dispatch endpoints. Keep production dispatch disabled.
2. Pin the issuer to `https://mcp-preview.crate.social` and the resource to `https://mcp-preview.crate.social/mcp`. Verify TLS, both discovery documents and a disposable reference-client authorization over HTTPS before handing over the URL.
3. Connect Muse through its Custom Connector flow. Connect Duet through the custom web connector if Duet exposes it. Record each callback and registration mode. Have the owner sign in and consent in the browser. Verify discovery, start, send, history, idempotent retry and reconnect with synthetic messages.
4. Verify two-owner isolation and revocation. For shared history, approve separate grants for the same owner, agent and Space and resume the same conversation ID. For separate Spaces, verify each conversation independently. Revoke the disposable grants and tear down the preview resources.


The [hosted binding template](hosted-preview.example.json) lists runtime inputs and placeholders. It is a configuration contract for review. Deploying it requires a concrete preview PDS service, a trusted cleanup scheduler and issuer adapter, and an issuer-backed retirement strategy for ambiguous refresh outcomes. Leave `FIXTURE_TESTS` unset in hosted environments. The Worker exposes `/fixture/revoke`, the alternate OAuth audience and simulated lost redirects only in the loopback test profile.

For Cloudflare, use Workers product Admin to create the dedicated Worker and Editor to deploy updates. Attaching the exact hostname requires zone-scoped Workers Routes Write on `crate.social`. Provision any preview backing stores and managed key through the scoped identities for those services. No permissions or hosted resources were changed during local qualification.

## Standalone PDS startup rehearsal

`pds-preview.example.json` is the input for `vlpds --dev-mode --spaces --listen 127.0.0.1:2583 --public-url http://127.0.0.1:2583 --exp711-preview-profile /absolute/preview/pds.json`. The profile binds recovery on a second loopback listener, requires an explicit injected wrapping key, and uses a dedicated `exp711-*` bucket on a loopback S3-compatible service. The filesystem object adapter cannot satisfy the PDS lease conditional-write requirement. Give this profile a dedicated local S3 service or an isolated sidecar with conditional-write support.

Run the standalone smoke test with paths to the built PDS, workerd, pinned issuer bundle and a disposable Moto server. The test launches a local emulator with synthetic credentials and uses the AWS CLI to create the disposable bucket.

```sh
node tools/spaces-mcp-auth-fixture/check-standalone-preview.mjs \
  /absolute/path/to/vlpds /absolute/path/to/workerd \
  /absolute/path/to/provider.mjs /absolute/path/to/moto_server
```

Set `dispatchSigner` to the Worker's trusted signing DID and `enrollmentRedirect` to the exact loopback PDS origin plus `/exp711/spaces-callback`. Set `enrollmentRelay: true` when staging the Worker. The browser signs in at the Worker, authorizes the scoped grant at the PDS, returns to the Worker using the callback form, then confirms MCP access. The Worker seals the owner session and callback state before writing them to a dedicated Durable Object instance. The state survives Worker restart, expires after two minutes, and is consumed once. An alarm reaps expired rows. Changing the preview bridge secret invalidates pending state.

Signed dispatch is mounted on the private listener. It reopens the scoped grant from sealed storage and uses create-only OAuth writes and signed Spaces credential reads. The startup-only command checks isolation and rejects unsolicited callback state and unsigned dispatch.

Run the opt-in browser smoke with a local Chromium or Chrome executable. The test starts the existing mock PLC and creates disposable identities, signed binding evidence, private Space membership, and a Worker signer. Chrome starts with a fresh profile and trusts the fixture's HTTPS certificate by its public-key pin.

```sh
EXP711_WORKERD=/absolute/path/to/workerd \
EXP711_OAUTH_PROVIDER=/absolute/path/to/provider.mjs \
EXP711_MOTO=/absolute/path/to/moto_server \
EXP711_CHROME=/absolute/path/to/chrome \
cargo test --offline --locked --test all standalone_browser_consent_and_chat -- --ignored --nocapture
```

This test drives both consent pages, the PDS-to-Worker relay and a separate HTTPS client callback. Its reference client initializes MCP, starts the conversation, sends a synthetic message, retries with the same ID, and checks the exact history entry.

The local issuer cleanup adapter checks the queued issuer, owner and client before retiring the exact old OAuth session. The preview scans configured bindings every five seconds. Hosted or external issuers still need independently authenticated cleanup adapters.

## Hosted configuration gates

Reserve `https://mcp-preview.crate.social/mcp` for the isolated Worker. Give `exp711-mcp-preview` a dedicated `PreviewIssuerStorage` Durable Object namespace and private bindings for the PDS sign-in and dispatch services. Set `ORIGIN` to the HTTPS origin, keep `FIXTURE_TESTS` unset, and set the Worker signer audience to the dedicated PDS service DID. Provision distinct Worker signing and bridge secrets and a stable, resolvable signer DID. The public preview exposes OAuth and MCP. The dispatch and recovery listeners require the private service binding.

The browser must be able to navigate to the PDS OAuth authorization and return through an HTTPS callback. Use a separate preview-only HTTPS PDS origin, such as `https://pds-mcp-preview.crate.social` once approved. Set the PDS public URL and `httpsEnrollment.pdsIssuer` to that exact origin. Set `enrollmentRedirect` to that origin plus `/exp711/spaces-callback`. The profile publishes the registered client document at `/exp711/client-metadata.json` with exactly that callback. Set the Worker's `OWNER_PDS_ORIGIN` to the PDS issuer. Use public TLS at the browser ingress and keep `/internal/agent-grant-recovery` and `/xrpc/vlpds.agent.dispatch` on the private service binding. Enable `ENROLLMENT_RELAY` after both connections are ready. The local smoke uses a disposable TLS reverse proxy and a pinned fixture CA instead of public ingress.

Start the isolated PDS without development mode. Keep the app listener and grant-recovery listener on separate loopback ports in the preview service. Provision distinct file-mounted session, admin, internal, PLC rotation, bridge, wrapping and S3 credentials. The normal PDS production secret checks run at startup. The profile requires the four CLI credential files and rejects a separate admin listener or admin proxy headers. It accepts a dedicated `exp711-*` bucket on a loopback S3-compatible sidecar with conditional-write support. The sidecar must use preview-only storage and never fall back to production storage.

```sh
vlpds --spaces --listen 127.0.0.1:2583 \
  --public-url https://pds-mcp-preview.crate.social \
  --service-did <preview-pds-did> --handle-domain <preview-handle-domain> \
  --exp711-preview-profile /run/exp711/pds.json \
  --jwt-secret-file /run/exp711/jwt-secret \
  --admin-token-file /run/exp711/admin-token \
  --internal-token-file /run/exp711/internal-token \
  --plc-mode directory --plc-url <preview-https-plc-origin> \
  --plc-rotation-key-file /run/exp711/plc-rotation-key
```

Terminate public TLS at the approved browser ingress for `pds-mcp-preview.crate.social`. Forward an explicit allowlist to `127.0.0.1:2583`. Include `/.well-known/oauth-authorization-server`, `/oauth/jwks`, `/oauth/par`, `/oauth/token`, `/oauth/revoke`, `/oauth/authorize` and its `sign-in`, `select`, and `consent` actions. Include the three registered `/exp711/` metadata and callback paths. The runtime uses `com.atproto.repo.describeRepo` and these `com.atproto.space` XRPCs through the same HTTPS authority: `getDelegationToken`, `authorizeSpaceSync`, `getRecord`, `listRecords`, and `createRecord`. Forward neither provisioning/signup nor admin, metrics, or recovery paths. The Worker's `OWNER_PDS` binding targets the preview app adapter, while `SPACES` targets the private recovery and signed-dispatch adapter on `127.0.0.1:2584`. Neither private adapter gets a public route. Preserve the configured HTTPS authority in transport and DPoP proofs. The isolated test uses a loopback TLS proxy with a pinned fixture CA, and the hosted profile omits `fixtureTls` and uses normal TLS trust. Hosted validation still needs the actual private binding, HTTPS PLC, and conditional-write store. Muse and Duet registration, callback URIs, and reconnect remain separate acceptance checks.

The deployer needs write access to the target Cloudflare account's Workers scripts and Durable Object namespace configuration, plus permission to attach the custom domain in the `crate.social` zone. Private routing and the PDS store and key each require permissions in their backing services. These permissions have not been probed for this candidate.

## Owner sign-in and grant boundaries

Set `ATPROTO_SIGN_IN=true` together with `ENROLLMENT_RELAY=true` to use the preview's identity-only ATProto OAuth registration at `/exp711/sign-in-client.json`. The initial Worker form accepts a handle. The password or other PDS authentication stays on the isolated PDS. The authorization code exchange verifies the configured issuer, token audience, client, DPoP key, and the DID resolved from the original handle. The PDS seals a five-minute app session with the preview wrapping key. Only private preview recovery accepts it. Recovery checks that the underlying identity grant and owner account are still active. Scoped Spaces OAuth remains a separate browser approval and grant. A subsequent MCP client can use the already enrolled Space after its own identity sign-in and chat consent.

Muse and Duet each receive their own OAuth registration and revocable grant for the MCP chat resource. The native browser smoke creates two independent MCP client grants and revokes the first through the issuer token endpoint. The survivor retains access to the same chat history. The isolated Worker records grant deletion in a Durable Object outbox and delivers exact owner, client, grant, approval and correlation evidence to the private PDS. The PDS tombstones the deleted MCP grant and keeps the scoped Spaces credential available to surviving clients. Preview deployment still needs the private service binding and retries must be observed in the hosted environment. Upstream Spaces revocation separately removes chat access for that binding. A planner client needs its own resource audience, registration, scopes, and revocation. Preview chat tokens should remain usable only at `/mcp` on the chat issuer. The first-party PDS account UI retains its existing client metadata, callbacks, and full account-session requirements.
