# Isolated Muse and Duet preview

## Rehearse locally

Run the following from a checkout that includes the verified PDS owner-session fixture.

```sh
export EXP711_WORKERD=/absolute/path/to/workerd
export EXP711_OAUTH_PROVIDER=/absolute/path/to/oauth-provider.js
sh tools/spaces-mcp-auth-fixture/validate-preview.sh
```

Use workerd 2026-11-17, the bundle from `@cloudflare/workers-oauth-provider` 1.2.1, and the locked Rust dependencies. The runner requires the Worker-specific pass markers. It starts only disposable IPv4 loopback listeners and removes the package and test state on normal exit. Each run allocates a fresh port. Its issuer is `http://127.0.0.1:<allocated-port>`, its resource is that origin plus `/mcp`, and its reference callback is that origin plus `/callback`. The command is an automated qualification harness. It does not keep an endpoint running for interactive clients.

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

Owner sign-in and consent must happen on the isolated service. The signed loopback fixture has an explicit browser form backed by real disposable PDS sign-in. Keep the fixture loopback-only. The hosted implementation needs its own secure session handling and owner consent UI. Bind each authorization request to a verified full PDS session, show the verified owner and exact approved Space, and require explicit approval. Follow the durable issuance sequence of reserve, claim, issuer completion, PDS binding, then redirect. Verify both sides of ident.link for two disposable owner–agent pairs. Give the server provider refreshable AT Protocol OAuth credentials with DPoP and exact Space scopes. Keep provider state, key material, and Space records separate from production. The current Worker/PDS harness qualifies the authentication and dispatch boundaries locally. The hosted browser flow and persistent credential provider still need wiring.

## Validate actual clients and clean up

1. Record each client's build, transport requirements, registration method, and exact callback URI. Check that it can reach the isolated origin and supports Streamable HTTP JSON and browser OAuth with S256 PKCE. Stop at the first unsupported or unverified step.
2. Connect Muse as owner A and Duet as owner B, or run one available client first. Verify resource discovery, consent, callback, token exchange, MCP initialization, and tool discovery. Use the same MCP endpoint for both owners and distinct browser sessions.
3. Start a chat, send synthetic text, retry the same message ID, and read history. Expect equal receipts and one record per owner under the correct author DID. Reconnect and read that history again. Try the other owner's conversation ID and expect denial for send and history.
4. Revoke owner A's grant. Confirm the old token and refresh fail, the denied send creates no record, and owner B can still chat. Keep the agent identities intact during this check.
5. Revoke both preview grants and verify issuer and upstream cleanup. Remove disposable client registrations, credentials, signer material, and test storage under the approved teardown scope. Shut down the preview. Record only redacted outcomes and client/version information.

A hosted run requires explicit approval for the chosen nonproduction origin and environment, disposable account and key issuance, and test data cleanup. No production deployment workflow is part of this runbook.
