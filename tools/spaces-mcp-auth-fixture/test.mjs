import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { packagePreview } from "./preview-package.mjs";
import { createServer } from "node:net";
import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";

const [workerd, provider] = process.argv.slice(2);
assert.ok(workerd && provider, "Usage: node test.mjs /absolute/path/to/workerd /path/to/oauth-provider.js");

// The Rust harness supplies only disposable credentials and a loopback target.
const input = createInterface({ input: process.stdin });
const commands = input[Symbol.asyncIterator]();
const { backend, ownerPds, bindings, foreignToken, verifyBinding, bridgeToken, signer, ownerPassword } = JSON.parse((await commands.next()).value);
assert.match(backend, /^127\.0\.0\.1:[1-9][0-9]{0,4}$/);
assert.equal(bindings.length, 2);
assert.ok(foreignToken);
const [alice, bob] = bindings;
const workerBindings = JSON.stringify({
  "a-chat": { token: alice.token },
  "b-chat": { token: bob.token },
});
const signedBindings = JSON.stringify({
  [Buffer.from(alice.authorDid).toString("base64url")]: { ownerDid: alice.authorDid },
  [Buffer.from(bob.authorDid).toString("base64url")]: { ownerDid: bob.authorDid },
});
assert.equal(Boolean(signer), Boolean(verifyBinding));

const reservation = createServer();
await new Promise((resolve, reject) => reservation.once("error", reject).listen(0, "127.0.0.1", resolve));
const address = `127.0.0.1:${reservation.address().port}`;
await new Promise((resolve) => reservation.close(resolve));

const origin = `${verifyBinding ? "https" : "http"}://${address}`;
const mcp = origin + "/mcp";
const other = origin + "/other";
async function phase(name) {
  console.log(`EXP711_PHASE ${name}`);
  assert.equal((await commands.next()).value, "ok");
}

const directory = await mkdtemp(join(tmpdir(), "exp711-mcp-auth-"));
let child;
try {
  if (verifyBinding) {
    await writeFile(join(directory, "issuer-tls.cnf"), `[req]
distinguished_name=dn
x509_extensions=extensions
prompt=no
[dn]
CN=127.0.0.1
[extensions]
subjectAltName=IP:127.0.0.1
`, { mode: 0o600 });
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
      "-config", "issuer-tls.cnf", "-keyout", "issuer-key.pem", "-out", "issuer-cert.pem"], { cwd: directory });
    setDefaultCACertificates([...getCACertificates("default"), await readFile(join(directory, "issuer-cert.pem"), "utf8")]);
    await phase(`issuer ${origin}`);
  }
  const config = await packagePreview({
    directory, provider, listener: address, backend,
    bindings: verifyBinding ? signedBindings : workerBindings,
    bridgeToken, signer, ownerPds,
  });
  async function startWorker() {
    child = spawn(workerd, ["serve", config], { stdio: ["ignore", "inherit", "inherit"] });
    let response;
    for (let attempt = 0; attempt < 40 && !response; attempt++) {
      assert.equal(child.exitCode, null, "workerd exited before readiness");
      response = await fetch(origin + "/.well-known/oauth-authorization-server").catch(() => undefined);
      if (!response) await delay(50);
    }
    assert.equal(response?.status, 200);
    return response;
  }
  async function stopWorker() {
    const stopped = new Promise((resolve) => child.once("exit", resolve));
    child.kill();
    await stopped;
  }
  const response = await startWorker();
  const metadata = await response.json();
  assert.equal(metadata.issuer, origin);
  assert.ok(metadata.code_challenge_methods_supported.includes("S256"));

  const challenge = await fetch(mcp, { method: "POST" });
  assert.equal(challenge.status, 401);
  const discovery = challenge.headers.get("WWW-Authenticate").match(/resource_metadata="([^"]+)"/)[1];
  const resourceMetadata = await (await fetch(discovery)).json();
  assert.equal(resourceMetadata.resource, mcp);
  assert.deepEqual(resourceMetadata.authorization_servers, [origin]);

  assert.equal(metadata.registration_endpoint, origin + "/register");
  const registration = await fetch(metadata.registration_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Disposable MCP client",
      redirect_uris: [origin + "/callback"],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }),
  });
  assert.equal(registration.status, 201, await registration.clone().text());
  const { client_id: clientId, redirect_uris: redirects, token_endpoint_auth_method: authMethod } =
    await registration.json();
  assert.ok(clientId);
  assert.deepEqual(redirects, [origin + "/callback"]);
  assert.equal(authMethod, "none");

  const token = (params) => fetch(metadata.token_endpoint, {
    method: "POST",
    body: new URLSearchParams({ client_id: clientId, ...params }),
  });

  function ownerHeaders(owner) {
    if (!verifyBinding) return { "X-Fixture-Owner": owner };
    const session = { "owner-a-session": alice.ownerSession, "owner-b-session": bob.ownerSession }[owner];
    assert.ok(session);
    return { "X-Fixture-Owner-Session": `Bearer ${session}` };
  }

  async function authorize(owner, resource, loseRedirect = false) {
    const verifier = randomBytes(32).toString("base64url");
    const state = randomBytes(16).toString("base64url");
    const redirect = origin + "/callback";
    const url = new URL(metadata.authorization_endpoint);
    url.search = new URLSearchParams({
      client_id: clientId, response_type: "code", redirect_uri: redirect,
      scope: "mcp:chat offline_access", resource, state,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      owner: "owner-b",
    });
    async function approve(url, headers = {}, password = ownerPassword) {
      if (!verifyBinding) return fetch(url, { headers: { ...ownerHeaders(owner), ...headers }, redirect: "manual" });
      const page = await fetch(url, { headers: ownerHeaders(owner), redirect: "manual" });
      assert.equal(page.status, 200);
      assert.equal(page.headers.get("Location"), null);
      const nonce = (await page.text()).match(/name="consent" value="([^"]+)"/)?.[1];
      assert.ok(nonce);
      const target = new URL("/authorize", origin);
      const handle = owner === "owner-a-session" ? alice.ownerHandle : bob.ownerHandle;
      const submit = (submissionOrigin, password) => fetch(target, {
        method: "POST", headers: { Origin: submissionOrigin, ...headers },
        body: new URLSearchParams({ consent: nonce, handle, password }), redirect: "manual",
      });
      assert.equal((await submit("http://127.0.0.1:1", ownerPassword)).status, 403);
      const result = await submit(origin, password);
      assert.equal((await submit(origin, ownerPassword)).status, 400);
      if (password !== ownerPassword) return result;
      assert.equal(result.status, 200);
      assert.equal(result.headers.get("Location"), null);
      const review = await result.text();
      const binding = owner === "owner-a-session" ? alice : bob;
      assert.ok(review.includes(binding.authorDid));
      assert.ok(review.includes(binding.conversationId));
      assert.ok(!review.includes(ownerPassword));
      const approval = review.match(/name="consent" value="([^"]+)"/)?.[1];
      assert.ok(approval);
      const confirm = () => fetch(target, {
        method: "POST", headers: { Origin: origin, ...headers },
        body: new URLSearchParams({ consent: approval }), redirect: "manual",
      });
      const response = await confirm();
      assert.equal((await confirm()).status, 400);
      return response;
    }
    if (loseRedirect) {
      if (verifyBinding) {
        const invalid = await approve(url, {}, "incorrect disposable password");
        assert.equal(invalid.status, 401);
        assert.equal(invalid.headers.get("Location"), null);
      }
      const denied = await approve(url, { "X-Fixture-Lose-Redirect": "yes" });
      assert.equal(denied.status, 503);
      assert.equal(denied.headers.get("Location"), null);
      // Reorder request parameters and add an ignored field. The validated
      // authorization parameters still identify the original operation.
      url.searchParams.sort();
      url.searchParams.set("untrusted", "ignored");
      const retry = await approve(url);
      assert.equal(retry.status, 409);
      assert.equal(retry.headers.get("Location"), null);
      return;
    }
    const approved = await approve(url);
    assert.equal(approved.status, 303, await approved.text());
    const callback = new URL(approved.headers.get("Location"));
    assert.equal(callback.searchParams.get("state"), state);
    assert.equal(callback.searchParams.get("iss"), origin);
    const exchange = await token({
      grant_type: "authorization_code", code: callback.searchParams.get("code"),
      code_verifier: verifier, redirect_uri: redirect, resource,
    });
    assert.equal(exchange.status, 200, await exchange.clone().text());
    const issued = await exchange.json();
    assert.equal(issued.resource, resource);
    assert.ok(issued.refresh_token);
    return issued;
  }

  if (verifyBinding) {
    const request = (owner, grantId) => fetch(origin + "/fixture/revoke", {
      headers: ownerHeaders(owner),
      ...(grantId ? { method: "POST", body: JSON.stringify({ grantId }) } : {}),
    });
    for (const headers of [{ "X-Fixture-Owner": "owner-a-session" },
      { "X-Fixture-Owner-Session": "Bearer invalid" },
      { "X-Fixture-Owner-Session": `Bearer ${foreignToken}` }]) {
      assert.equal((await fetch(origin + "/fixture/revoke", { headers })).status, 401);
    }
    await authorize("owner-a-session", mcp, true);
    const lostGrants = await (await request("owner-a-session")).json();
    assert.equal(lostGrants.length, 1);
    assert.equal((await request("owner-b-session", lostGrants[0])).status, 404);
    assert.equal((await request("owner-a-session", lostGrants[0])).status, 204);
    assert.deepEqual(await (await request("owner-a-session")).json(), []);
    console.log("Passed browser sign-in and one-time OAuth consent over the disposable PDS route");
    console.log("Passed OAuth consent bound to authenticated disposable PDS owner sessions");
  }

  const a = await authorize("owner-a-session", mcp);
  const b = await authorize("owner-b-session", mcp);
  const wrongAudience = await authorize("owner-a-session", other);
  const rpc = (access, method, params, headers = {}) => fetch(mcp, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${access}`,
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      "MCP-Protocol-Version": "2025-06-18",
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0", ...(method.startsWith("notifications/") ? {} : { id: 1 }), method, params,
    }),
  });
  const tool = (access, name, args, headers) => rpc(access, "tools/call", { name, arguments: args }, headers);
  const read = (grant, conversationId) => tool(grant.access_token, "spaces_chat_history", { conversationId });
  const send = (grant, conversationId, messageId, text, headers) =>
    tool(grant.access_token, "spaces_chat_send", { conversationId, messageId, text }, headers);
  async function result(response) {
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.jsonrpc, "2.0");
    assert.equal(body.id, 1);
    assert.ok(body.result);
    return body.result.structuredContent;
  }

  if (verifyBinding) {
    await stopWorker();
    await startWorker();
  }

  for (const issued of [a, b]) {
    const initialized = await rpc(issued.access_token, "initialize", {
      protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "fixture", version: "1" },
    });
    assert.equal((await initialized.json()).result.protocolVersion, "2025-06-18");
    assert.equal((await rpc(issued.access_token, "notifications/initialized")).status, 202);
    const listing = await rpc(issued.access_token, "tools/list");
    assert.deepEqual((await listing.json()).result.tools.map(({ name }) => name),
      ["spaces_chat_start", "spaces_chat_send", "spaces_chat_history"]);
  }

  for (const [grant, owner, text] of [[a, alice, "OAuth owner A"], [b, bob, "OAuth owner B"]]) {
    const { conversationId, authorDid } = owner;
    assert.deepEqual(await result(await tool(grant.access_token, "spaces_chat_start", {})), { conversationId });
    const receipt = await result(await send(grant, conversationId, "worker", text));
    assert.deepEqual(receipt, await result(await send(grant, conversationId, "worker", text)));
    assert.equal(receipt.authorDid, authorDid);
    const history = await result(await read(grant, conversationId));
    assert.deepEqual(history.messages.filter((entry) => entry.messageId === "worker").map((entry) =>
      [entry.cid, entry.authorDid, entry.text]), [[receipt.cid, authorDid, text]]);
  }

  const unavailable = { code: "conversation_unavailable" };
  assert.deepEqual(await result(await read(a, bob.conversationId)), unavailable);
  assert.deepEqual(await result(await read(b, alice.conversationId)), unavailable);
  assert.deepEqual(await result(await send(a, bob.conversationId, "crossowner", "denied",
    { "X-Fixture-Owner": "owner-b-session" })), unavailable);
  assert.deepEqual(await result(await send(b, alice.conversationId, "crossowner", "denied")), unavailable);
  assert.equal((await read(wrongAudience, alice.conversationId)).status, 401);
  assert.equal((await read({ access_token: foreignToken }, alice.conversationId)).status, 401);

  if (verifyBinding) {
    await phase("unsigned-probe");
    for (const half of ["endorsement", "declaration"]) {
      await phase(`remove-${half}`);
      assert.equal((await read(a, alice.conversationId)).status, 403);
      assert.equal((await send(a, alice.conversationId, half, "denied")).status, 403);
      assert.equal((await tool(a.access_token, "spaces_chat_start", {})).status, 403);
      assert.ok((await result(await read(b, bob.conversationId))).messages.some(({ text }) => text === "OAuth owner B"));
      const surviving = await result(await send(b, bob.conversationId, half, "Other owner still writes"));
      assert.equal(surviving.authorDid, bob.authorDid);
      await phase(`restore-${half}`);
      assert.deepEqual((await result(await read(a, alice.conversationId))).messages.map(({ messageId }) => messageId),
        ["worker"]);
    }
    assert.equal((await tool(a.access_token, "spaces_chat_history", { conversationId: alice.conversationId }, {
      "X-Exp711-User": "owner-b", "X-Exp711-Grant": "forged-by-client",
    })).status, 200);
    await phase("arm-durable-revocation");
    assert.equal((await send(a, alice.conversationId, "race", "must not persist")).status, 403);
    assert.equal((await read(a, alice.conversationId)).status, 403);
    assert.equal((await rpc(a.access_token, "ping")).status, 403, "PDS denies even stateless RPC after revocation");
    assert.equal((await read(b, bob.conversationId)).status, 200);
    const surviving = await result(await send(b, bob.conversationId, "race", "Other owner still writes"));
    assert.equal(surviving.authorDid, bob.authorDid);
    const beforeRestart = await result(await read(b, bob.conversationId));
    await phase("restart-private-pds");
    assert.deepEqual(await result(await read(b, bob.conversationId)), beforeRestart);
    assert.deepEqual(await result(await send(b, bob.conversationId, "race", "Other owner still writes")), surviving);
    assert.deepEqual(await result(await read(b, bob.conversationId)), beforeRestart);
    assert.equal((await read(a, alice.conversationId)).status, 401);
    const grants = await fetch(origin + "/fixture/revoke", { headers: ownerHeaders("owner-b-session") });
    assert.equal(grants.status, 200);
    const [grantId] = await grants.json();
    const revoke = await fetch(origin + "/fixture/revoke", {
      method: "POST", headers: ownerHeaders("owner-b-session"), body: JSON.stringify({ grantId }),
    });
    assert.equal(revoke.status, 204);
    assert.equal((await send(b, bob.conversationId, "afterrevoke", "denied")).status, 401);
    assert.equal((await read(b, bob.conversationId)).status, 401);
    const revokedRefresh = await token({ grant_type: "refresh_token", refresh_token: b.refresh_token, resource: mcp });
    assert.equal((await revokedRefresh.json()).error, "invalid_grant");
    console.log("Passed the same Worker grant across Worker and PDS restarts, with history, retry and revocation");
    console.log("Passed fresh ident.link verification at MCP dispatch on already-issued tokens");
  }

  if (!verifyBinding) {
    const ownerRequest = (owner, options = {}) => fetch(origin + "/fixture/revoke", {
      ...options, headers: ownerHeaders(owner),
    });
    const [grantId] = await (await ownerRequest("owner-b-session")).json();
    const revoke = (owner) => ownerRequest(owner, {
      method: "POST", body: JSON.stringify({ grantId }),
    });
    assert.equal((await revoke("owner-a-session")).status, 404);
    assert.equal((await read(b, bob.conversationId)).status, 200);
    assert.equal((await revoke("owner-b-session")).status, 204);
    assert.equal((await read(b, bob.conversationId)).status, 401);
    assert.equal((await send(b, bob.conversationId, "revoked", "denied")).status, 401);
    const revoked = await token({ grant_type: "refresh_token", refresh_token: b.refresh_token, resource: mcp });
    assert.equal(revoked.status, 400);
    assert.equal((await revoked.json()).error, "invalid_grant");
    assert.equal((await read(a, alice.conversationId)).status, 200);
  }
  if (verifyBinding) console.log("Passed issuer restart with existing OAuth tokens and signed private Spaces chat");
  console.log("Passed OAuth-authorized Spaces writes/history, two-owner binding, audience isolation, and grant revocation");
} finally {
  input.close();
  process.stdin.destroy();
  if (child && child.exitCode === null && child.signalCode === null) {
    const stopped = new Promise((resolve) => child.once("exit", resolve));
    child.kill();
    await stopped;
  }
  await rm(directory, { recursive: true, force: true });
}
