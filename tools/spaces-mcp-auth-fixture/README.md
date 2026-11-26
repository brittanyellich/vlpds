# First MCP Spaces chat test

## Run the disposable reference

Use Node and the repository's Rust toolchain. The verified combination used Node 26.12.1, workerd 2026-11-17, and the `dist/oauth-provider.js` bundle from `@cloudflare/workers-oauth-provider` 1.2.1. Set both paths to locally available artifacts.

```sh
export EXP711_WORKERD=/absolute/path/to/workerd
export EXP711_OAUTH_PROVIDER=/absolute/path/to/oauth-provider.js
test -x "$EXP711_WORKERD" &&
  test -r "$EXP711_OAUTH_PROVIDER" &&
  cargo test --locked --test all -- ident_link_binding spaces_mcp_chat --nocapture
```

The shell guards matter because the Rust tests skip the Worker-specific checks when both paths are unset. Look for the OAuth-authorized Spaces writes/history and fresh ident.link verification lines, followed by a passing test result. The Rust harness starts its own PDS, PLC fixture, and Worker on loopback. It generates disposable accounts, tokens, and signing keys and exercises the real Spaces XRPCs. The Worker authorization state is in memory. The command exits and tears down the listeners.

The reference exercises protected-resource and issuer discovery, dynamic client registration via issuer metadata, authorization code with S256 PKCE, resource-bound token exchange, MCP initialization and tool discovery, chat start/send/history, stable retry receipts, two-owner isolation, and revocation. It also covers an issuer grant whose redirect is lost. The retry gets no second grant or redirect, and the owner can explicitly revoke the original grant.

The Worker calls a private loopback fixture bridge that uses the PDS admission verifier. A separate Rust test exercises the normal opt-in PDS signed dispatch route, including scoped session reopening after restart and revocation during session acquisition. The signed Worker path verifies a disposable full PDS session at consent and derives the owner DID from that session. The harness supplies the session in memory and uses the OAuth library’s standard registration endpoint. A browser-facing sign-in and consent UI remains a separate integration. These checks qualify the two boundaries locally. The harness is a test runner and does not expose a persistent endpoint for Muse or Duet.

## Validate the isolated package

Run `node --test tools/spaces-mcp-auth-fixture/preview-package.test.mjs` before running the Rust command. The harness explicitly stages two Worker modules and a private workerd configuration in a temporary directory. Both the listener and backend must be distinct IPv4 loopback addresses. The harness removes the directory when it exits. This package is for disposable local qualification. Keep it off public interfaces and tunnels, since owner sign-in is simulated.

To qualify a client that cannot reach loopback, first provide a separate authenticated preview deployment. Its public issuer and resource must agree with discovery and token audience, and its private dispatch target must use the configured signer and owner-scoped session provider. Use isolated grant and Space storage and a real owner consent flow. No hosted deployment package is provided here.

See the [isolated client preview runbook](CLIENT-PREVIEW.md) for the validated command, hosted origin and consent checklist, and teardown steps.

## Qualify Muse and Duet

1. Record the exact client build and execution environment. For each client, confirm it can reach the test endpoint, supports MCP Streamable HTTP with JSON responses, and can complete browser-based OAuth authorization code with S256 PKCE. Record which registration path it supports and its exact redirect URI. Check whether it requires SSE or a server session ID before proceeding. The fixture uses protocol version `2025-06-18` and a stateless JSON transport. A deployment may need an adapter if a client requires a transport feature outside that contract.
2. Prepare a test endpoint at an origin reachable from the client, using HTTPS or loopback if the client supports it. Configure issuer discovery, protected-resource discovery, and registration or pre-registration with the verified callback. Wire authenticated owner sign-in and consent to durable grant issuance and cleanup, with a signed PDS hop and a server-owned provider using securely stored, refreshable, exact-Space AT Protocol OAuth credentials with DPoP. The standalone vlPDS route defaults off. The fixture OAuth issuer and its registration endpoint are confined to the harness.
3. Bootstrap two disposable owner–agent pairs. For each pair, verify the owner's explicit consent, both sides of the ident.link binding, and access to one private Space. Use the same MCP resource URL for both owners and keep the two browser sessions and grants distinct. Capture client and protocol versions and redacted outcomes. Omit tokens, codes, signing keys, and private Space identifiers.
4. Connect Muse as owner A and Duet as owner B, or execute the same sequence one client at a time. Confirm the client follows the 401 discovery challenge, reaches the expected issuer, presents owner consent, returns to the registered callback, and completes `initialize`, `notifications/initialized`, and `tools/list`. Record the first unsupported step if a client cannot complete the sequence.
5. In each client, run `spaces_chat_start` with empty arguments and retain the returned conversation ID. Run `spaces_chat_send` with that ID, a stable synthetic message ID such as `first`, and synthetic text. Repeat the same request and compare receipts. Run `spaces_chat_history` with that conversation ID and verify exactly one copy of the message under the expected author. Resend a changed body under the same message ID and expect `idempotency_conflict`. Verify the agent's reply under the agent DID if the pilot includes agent invocation.
6. Reconnect and resume history after restarting the test PDS. Verify both owners can read their own persisted messages. Try the other owner's conversation ID with each grant and require denial for both send and history. Revoke owner A's test grant, then require denial with its old access token, failure to refresh, and no new record. Confirm owner B continues to send and read history and that owner A's agent identity still exists. Repeat the client-specific checks with owners swapped if either client behaves differently.

The EXP-711 issue identifies Muse and Duet as candidates. No verified client build, registration method, callback URI, or actual-client trace is available in the local references. Record those details from each approved test client before creating any registration.
