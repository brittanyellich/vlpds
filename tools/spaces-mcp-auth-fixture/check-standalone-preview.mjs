import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { request as httpRequest } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { setTimeout as delay } from "node:timers/promises";
import { createInterface } from "node:readline";
import { authorizeSetup, startBrowser } from "./standalone-browser.mjs";
import { packagePreview } from "./preview-package.mjs";

const [pdsBinary, workerd, provider, moto, chrome] = process.argv.slice(2);
assert.ok(pdsBinary && workerd && provider && moto, "Usage: node check-standalone-preview.mjs /path/to/vlpds /path/to/workerd /path/to/provider.mjs /path/to/moto_server");
const input = chrome && createInterface({ input: process.stdin });
const commands = input && input[Symbol.asyncIterator]();
const local = commands && JSON.parse((await commands.next()).value);
if (local) assert.match(local.plc, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/);
const directory = await mkdtemp(join(tmpdir(), "exp711-standalone-"));
const processes = [];
const env = { PATH: process.env.PATH, TMPDIR: directory };
const sockets = Array.from({ length: 6 }, () => createServer());
const randomSecret = () => randomBytes(32).toString("hex");

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill();
  const timer = setTimeout(() => child.kill("SIGKILL"), 6000);
  try {
    await exited;
  } finally {
    clearTimeout(timer);
  }
}

async function ready(child, url) {
  for (let attempt = 0; attempt < 100; attempt++) {
    assert.equal(child.exitCode, null, "preview process exited during startup");
    const response = await fetch(url, { signal: AbortSignal.timeout(1000) }).catch(() => undefined);
    if (response?.ok) return response;
    await delay(50);
  }
  assert.fail("preview listener did not become ready");
}

let clientCallback;
let pdsProxy;
try {
  for (const socket of sockets) {
    await new Promise((resolve, reject) => socket.once("error", reject).listen(0, "127.0.0.1", resolve));
  }
  const [pds, recovery, worker, storage, clientListener, pdsTls] = sockets.map((socket) => `127.0.0.1:${socket.address().port}`);
  for (const socket of sockets) await new Promise((resolve) => socket.close(resolve));
  const issuer = `https://${worker}`;
  const serviceToken = randomSecret();
  const storageOrigin = `http://${storage}`;
  const bucket = "exp711-standalone";
  const accessKeyFile = join(directory, "s3-access");
  const secretKeyFile = join(directory, "s3-secret");
  const accessKey = randomSecret();
  const secretKey = randomSecret();
  await writeFile(accessKeyFile, accessKey, { mode: 0o600 });
  await writeFile(secretKeyFile, secretKey, { mode: 0o600 });
  const s3 = spawn(moto, ["-H", "127.0.0.1", "-p", storage.split(":")[1]], {
    env, stdio: ["ignore", "ignore", "ignore"],
  });
  processes.push(s3);
  await ready(s3, storageOrigin);
  execFileSync("aws", ["--endpoint-url", storageOrigin, "s3api", "create-bucket", "--bucket", bucket], {
    env: { ...env, AWS_ACCESS_KEY_ID: accessKey, AWS_SECRET_ACCESS_KEY: secretKey, AWS_DEFAULT_REGION: "us-east-1" },
    stdio: "ignore",
  });
  const wrappingKeyFile = join(directory, "wrapping-key");
  const serviceTokenFile = join(directory, "service-token");
  const profile = join(directory, "pds.json");
  await writeFile(wrappingKeyFile, randomSecret(), { mode: 0o600 });
  await writeFile(serviceTokenFile, serviceToken, { mode: 0o600 });
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signer = local?.signer ?? { iss: "did:web:signer.invalid", aud: "did:web:pds.invalid",
    method: "vlpds.agent.dispatch", jwk: privateKey.export({ format: "jwk" }) };
  await writeFile(join(directory, "tls.cnf"), "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1,DNS:preview-pds.test\n", { mode: 0o600 });
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-config", "tls.cnf", "-keyout", "issuer-key.pem", "-out", "issuer-cert.pem"], { cwd: directory, env, stdio: "ignore" });
  const pem = await readFile(join(directory, "issuer-cert.pem"), "utf8");
  setDefaultCACertificates([...getCACertificates("default"), pem]);
  const pdsOrigin = local ? `https://preview-pds.test:${pdsTls.split(":")[1]}` : `http://${pds}`;
  const privatePds = `http://${pds}`;
  const fetchPds = (url, options) => fetch(url.replace(pdsOrigin, local ? `https://${pdsTls}` : pdsOrigin), options);
  if (local) {
    const key = await readFile(join(directory, "issuer-key.pem"));
    pdsProxy = createHttpsServer({ cert: pem, key }, (request, response) => {
      const upstream = httpRequest(privatePds + request.url, {
        method: request.method, agent: false, headers: { ...request.headers, "x-forwarded-proto": "https" },
      }, (result) => {
        response.writeHead(result.statusCode, result.headers);
        result.pipe(response);
      });
      upstream.on("error", () => response.writeHead(502).end());
      request.pipe(upstream);
    });
    await new Promise((resolve, reject) =>
      pdsProxy.once("error", reject).listen(Number(pdsTls.split(":")[1]), "127.0.0.1", resolve));
  }
  const profileConfig = {
    recoveryListen: recovery, wrappingKeyFile, issuer, serviceTokenFile, bindings: {},
    dispatchSigner: signer.iss, enrollmentRedirect: `${pdsOrigin}/exp711/spaces-callback`,
    ...(local && { httpsEnrollment: { pdsIssuer: pdsOrigin, fixtureTls: {
      caFile: join(directory, "issuer-cert.pem"), listener: pdsTls,
    } } }),
    storage: { endpoint: storageOrigin, bucket, accessKeyFile, secretKeyFile },
  };
  await writeFile(profile, JSON.stringify(profileConfig), { mode: 0o600 });
  const args = ["--dev-mode", "--spaces", "--listen", pds, "--public-url", pdsOrigin,
    "--exp711-preview-profile", profile, "--service-did", signer.aud, "--plc-mode", local ? "directory" : "unregistered", "--shards", "4", "--memory-budget-mb", "8192", "--handle-domain", "vlpds.test"];
  if (local) {
    const rotation = join(directory, "rotation-key");
    await writeFile(rotation, local.rotation, { mode: 0o600 });
    args.push("--plc-url", local.plc, "--plc-rotation-key-file", rotation);
    for (const authority of ["ident.link", "example.com", "mcpchat.example.com"]) {
      args.push("--lexicon-authority-override", `${authority}=${signer.iss}`);
    }
  }
  async function startPds() {
    const child = spawn(pdsBinary, args, { env, stdio: ["ignore", "ignore", "inherit"] });
    processes.push(child);
    await ready(child, privatePds + "/xrpc/_health");
    return child;
  }

  const first = await startPds();
  const password = randomSecret();
  const signIn = (method) => fetchPds(pdsOrigin + "/xrpc/com.atproto.server." + method, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ handle: "preview.vlpds.test", identifier: "preview.vlpds.test", email: "preview@example.invalid", password }),
  });
  const account = await signIn("createAccount");
  assert.equal(account.status, 200, await account.clone().text());
  const { did, accessJwt } = await account.json();
  const grantPath = "/internal/agent-grant-recovery";
  const probe = (origin, token) => fetchPds(origin + grantPath, {
    method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${serviceToken}`,
      ...(token ? { "X-Vlpds-Owner-Session": `Bearer ${token}` } : {}) },
    body: JSON.stringify({ operation: "owner" }),
  });
  assert.equal((await probe(pdsOrigin)).status, 404);
  assert.equal((await probe(`http://${recovery}`)).status, 403);

  let browser;
  let binding = { agent: "did:web:preview-agent.invalid", space: `at:space/${did}/com.example.mcpchat/preview` };
  if (local) {
    browser = await startBrowser({ chrome, directory, pem, env, processes });
    const provision = await fetchPds(pdsOrigin + "/xrpc/vlpds.agent.provision", {
      method: "POST", headers: { Authorization: `Bearer ${accessJwt}`, "Content-Type": "application/json" },
      body: JSON.stringify({ operationId: "standalone", handle: "agent.vlpds.test",
        email: "agent@example.invalid", password: randomSecret() }),
    });
    assert.equal(provision.status, 200, await provision.clone().text());
    const agent = await provision.json();
    assert.equal(agent.status, "ready");
    console.log("EXP711_DECLARE " + JSON.stringify({ owner: did, agent: agent.did }));
    assert.equal((await commands.next()).value, "ok");
    input.close();
    process.stdin.pause();
    const scope = "atproto repo:link.ident.endorsement?action=create " +
      `space:com.example.mcpchat?authority=${did}&skey=preview&manage=create&manage=update&collection=com.example.mcpchat.thread`;
    const setup = await authorizeSetup(browser, pdsOrigin, privatePds + "/exp711/spaces-callback",
      "preview.vlpds.test", password, scope, fetchPds);
    const endorsement = await setup("com.atproto.repo.createRecord", {
      repo: did, collection: "link.ident.endorsement", rkey: agent.did,
      record: { $type: "link.ident.endorsement", agent: agent.did }, validate: false,
    });
    assert.equal(endorsement.status, 200, await endorsement.clone().text());
    const created = await setup("com.atproto.space.createSpace", {
      spaceType: "com.example.mcpchat", skey: "preview", policy: { $type: "com.atproto.memberspace.policy" },
    });
    assert.equal(created.status, 200, await created.clone().text());
    const { space } = await created.json();
    assert.equal(space, binding.space);
    const member = await setup("com.atproto.memberspace.putMembers", {
      space, members: [{ did: agent.did, read: true, write: true }],
    });
    assert.equal(member.status, 200, await member.clone().text());
    binding = { agent: agent.did, space };
  }
  const config = await packagePreview({
    directory, provider, listener: worker, backend: recovery, ownerPds: pds, ownerPdsOrigin: pdsOrigin,
    bindings: local ? JSON.stringify({ [Buffer.from(did).toString("base64url")]: { ownerDid: did } }) : "{}",
    bridgeToken: serviceToken, fixtureTests: false, enrollmentRelay: true, signer,
  });
  function startWorker() {
    const child = spawn(workerd, ["serve", config], { env, stdio: ["ignore", "ignore", "inherit"] });
    processes.push(child);
    return child;
  }
  let workerProcess = startWorker();
  const metadataPath = issuer + "/.well-known/oauth-authorization-server";
  const metadata = await ready(workerProcess, metadataPath);
  const oauth = await metadata.json();
  assert.equal(oauth.issuer, issuer);
  const resource = await fetch(issuer + "/.well-known/oauth-protected-resource/mcp");
  assert.equal((await resource.json()).resource, issuer + "/mcp");
  assert.equal((await fetch(issuer + "/fixture/revoke")).status, 404);
  await stop(first);
  profileConfig.bindings[did] = binding;
  await writeFile(profile, JSON.stringify(profileConfig), { mode: 0o600 });
  const activePds = await startPds();
  const resumed = await signIn("createSession");
  assert.equal(resumed.status, 200);
  const credentials = await resumed.json();
  assert.equal(credentials.did, did);
  const owner = await probe(`http://${recovery}`, credentials.accessJwt);
  assert.equal(owner.status, 200);
  assert.deepEqual(await owner.json(), { did, binding });
  assert.equal((await probe(`http://${recovery}`)).status, 403);
  const callback = await fetchPds(profileConfig.enrollmentRedirect + "?" + new URLSearchParams({
    iss: pdsOrigin, code: "cod-fixture.value", state: "mcp-unknown",
  }));
  assert.equal(callback.status, 200);
  const wrongIssuer = await fetchPds(profileConfig.enrollmentRedirect + "?" + new URLSearchParams({
    iss: issuer, code: "cod-fixture.value", state: "mcp-unknown",
  }));
  assert.equal(wrongIssuer.status, 400);
  if (local) {
    const metadata = await fetchPds(pdsOrigin + "/exp711/client-metadata.json");
    assert.equal(metadata.status, 200);
    const registration = await metadata.json();
    assert.deepEqual(registration.redirect_uris, [profileConfig.enrollmentRedirect]);
    assert.ok(!JSON.stringify(registration).includes(did), "client metadata must not reveal the owner or Space");
    const wrongCallback = pdsOrigin + "/exp711/wrong-callback";
    assert.equal((await fetchPds(wrongCallback)).status, 404);
    await authorizeSetup(browser, pdsOrigin, wrongCallback, "preview.vlpds.test", password, "atproto",
      fetchPds, registration.client_id);
  }
  assert.equal(callback.headers.get("cache-control"), "no-store");
  assert.ok((await callback.text()).includes(`action="${issuer}/spaces-callback"`));
  const relay = await fetch(issuer + "/spaces-callback", {
    method: "POST", headers: { Origin: pdsOrigin },
    body: new URLSearchParams({ issuer: pdsOrigin, code: "cod-fixture.value", state: "mcp-unknown" }),
  });
  assert.equal(relay.status, 400);
  const dispatch = { method: "POST", body: "{}" };
  assert.equal((await fetchPds(pdsOrigin + "/xrpc/vlpds.agent.dispatch", dispatch)).status, 501);
  assert.equal((await fetch(`http://${recovery}/xrpc/vlpds.agent.dispatch`, dispatch)).status, 401);
  console.log("Passed standalone restart, HTTPS discovery, callback relay boundaries, and private dispatch isolation");
  if (local) {
    const visible = await fetchPds(pdsOrigin + "/xrpc/vlpds.agent.listAgents", {
      headers: { Authorization: `Bearer ${credentials.accessJwt}` },
    });
    assert.equal(visible.status, 200);
    assert.deepEqual((await visible.json()).agents, [{ did: binding.agent, handle: "agent.vlpds.test" }]);
    let callbackRequests = 0;
    const key = await readFile(join(directory, "issuer-key.pem"));
    clientCallback = createHttpsServer({ cert: pem, key }, (request, response) => {
      if (request.method !== "GET" || !request.url.startsWith("/client-callback?")) {
        response.writeHead(404).end();
        return;
      }
      callbackRequests++;
      response.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer" }).end("<title>Disposable MCP callback</title>");
    });
    await new Promise((resolve, reject) =>
      clientCallback.once("error", reject).listen(Number(clientListener.split(":")[1]), "127.0.0.1", resolve));
    const redirect = `https://${clientListener}/client-callback`;
    const register = await fetch(oauth.registration_endpoint, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: "Standalone fixture", redirect_uris: [redirect],
        token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"] }),
    });
    assert.equal(register.status, 201);
    const { client_id } = await register.json();
    const verifier = randomBytes(32).toString("base64url");
    const state = randomSecret();
    const resource = issuer + "/mcp";
    const start = oauth.authorization_endpoint + "?" + new URLSearchParams({
      client_id, response_type: "code", redirect_uri: redirect, scope: "mcp:chat offline_access", resource, state,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256",
    });
    await browser.navigate(start);
    await browser.submit('form[action="/authorize"] button', { handle: "preview.vlpds.test", password });
    await browser.wait(`document.body.textContent.includes(${JSON.stringify(binding.space)})`, "Worker binding review");
    await browser.submit('form[action="/authorize"] button');
    await browser.pdsConsent(pdsOrigin, "preview.vlpds.test", password);
    await browser.wait('document.title === "Return to Spaces preview"', "PDS callback relay page");
    // The callback must survive loss of the Worker isolate that initiated it.
    await stop(workerProcess);
    workerProcess = startWorker();
    await ready(workerProcess, metadataPath);
    const relayBody = await browser.evaluate('Object.fromEntries(new FormData(document.querySelector("form")))');
    await browser.submit('form[action$="/spaces-callback"] button');
    await browser.wait(`location.pathname === "/spaces-callback" && document.body.textContent.includes(${JSON.stringify(binding.space)})`,
      "successful scoped enrollment");
    const replay = await fetch(issuer + "/spaces-callback", {
      method: "POST", headers: { Origin: pdsOrigin }, body: new URLSearchParams(relayBody),
    });
    assert.equal(replay.status, 400);
    await browser.submit('form[action="/authorize"] button');
    const callback = new URL(await browser.wait(
      `location.href.startsWith(${JSON.stringify(redirect + "?")}) && location.href`, "MCP client callback",
    ));
    assert.equal(callbackRequests, 1);
    assert.equal(callback.searchParams.get("state"), state);
    assert.equal(callback.searchParams.get("iss"), issuer);
    browser.close();
    const exchange = await fetch(oauth.token_endpoint, {
      method: "POST", body: new URLSearchParams({ client_id, grant_type: "authorization_code", code: callback.searchParams.get("code"),
        redirect_uri: redirect, code_verifier: verifier, resource }),
    });
    if (!exchange.ok) assert.fail("MCP token exchange failed: " + await exchange.text());
    const token = await exchange.json();
    assert.equal(token.resource, resource);
    async function rpc(method, params) {
      const reply = await fetch(resource, {
        method: "POST", headers: {
          Authorization: `Bearer ${token.access_token}`, "Content-Type": "application/json",
          Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18",
        }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      assert.equal(reply.status, 200, await reply.clone().text());
      const response = await reply.json();
      assert.equal(response.id, 1);
      assert.ok(response.result, JSON.stringify(response));
      assert.ok(!response.result.isError, JSON.stringify(response.result.structuredContent));
      return response.result;
    }
    const call = async (name, args) => (await rpc("tools/call", { name, arguments: args })).structuredContent;
    const initialized = await rpc("initialize", {
      protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "standalone-smoke", version: "1" },
    });
    assert.equal(initialized.protocolVersion, "2025-06-18");
    const conversationId = "preview";
    assert.deepEqual(await call("spaces_chat_start", {}), { conversationId });
    const args = { conversationId, messageId: "standalone", text: "Synthetic standalone preview" };
    const sent = await call("spaces_chat_send", args);
    assert.equal(sent.authorDid, did);
    assert.equal(sent.messageId, args.messageId);
    assert.match(sent.cid, /^bafy/);
    await stop(activePds);
    await startPds();
    assert.deepEqual(await call("spaces_chat_send", args), sent);
    assert.deepEqual(await call("spaces_chat_history", { conversationId }), {
      conversationId, messages: [{ ...sent, text: args.text }],
    });
    console.log("Passed real Chrome consent, one-time scoped callback, signed standalone HTTPS send, PDS restart, retry and history");
  }
} finally {
  for (const child of processes.reverse()) await stop(child);
  for (const server of [clientCallback, pdsProxy]) {
    if (!server?.listening) continue;
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    });
  }
  for (const socket of sockets) if (socket.listening) socket.close();
  await rm(directory, { recursive: true, force: true });
}
