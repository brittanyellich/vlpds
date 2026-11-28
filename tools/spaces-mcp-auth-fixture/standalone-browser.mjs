import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID, X509Certificate } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

export async function startBrowser({ chrome, directory, pem, env, processes }) {
  const profile = join(directory, "chrome");
  const spki = new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" });
  const pin = createHash("sha256").update(spki).digest("base64");
  const process = spawn(chrome, [
    "--headless", "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
    "--disable-component-update", "--disable-sync", "--no-proxy-server",
    "--host-resolver-rules=MAP preview-pds.test 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    "--remote-debugging-port=0", `--user-data-dir=${profile}`,
    `--ignore-certificate-errors-spki-list=${pin}`, "about:blank",
  ], { env, stdio: "ignore" });
  processes.push(process);
  let endpoint;
  for (let attempt = 0; attempt < 150 && !endpoint; attempt++) {
    assert.equal(process.exitCode, null, "Chrome exited before readiness");
    const active = await readFile(join(profile, "DevToolsActivePort"), "utf8").catch(() => "");
    if (active) {
      const targets = await fetch(`http://127.0.0.1:${active.split("\n")[0]}/json/list`)
        .then((response) => response.json()).catch(() => []);
      endpoint = targets.find((target) => target.type === "page")?.webSocketDebuggerUrl;
    }
    if (!endpoint) await delay(50);
  }
  assert.ok(endpoint, "Missing disposable Chrome page");
  const socket = new WebSocket(endpoint);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  let id = 0;
  const pending = new Map();
  socket.addEventListener("message", ({ data }) => {
    const message = JSON.parse(data);
    pending.get(message.id)?.(message);
  });
  async function command(method, params) {
    const key = ++id;
    const result = Promise.withResolvers();
    pending.set(key, result.resolve);
    socket.send(JSON.stringify({ id: key, method, params }));
    const deadline = setTimeout(() => result.reject(new Error(`Chrome timed out in ${method}`)), 5000);
    try {
      const response = await result.promise;
      assert.ok(!response.error, `Chrome command failed: ${method}`);
      return response.result;
    } finally {
      clearTimeout(deadline);
      pending.delete(key);
    }
  }

  const evaluate = async (expression) => {
    const response = await command("Runtime.evaluate", { expression, returnByValue: true });
    assert.ok(!response.exceptionDetails, "Browser fixture expression failed");
    return response.result.value;
  };
  async function wait(expression, stage) {
    for (let attempt = 0; attempt < 150; attempt++) {
      // The JavaScript context can disappear during a form navigation.
      const value = await evaluate(expression).catch(() => undefined);
      if (value) return value;
      await delay(50);
    }
    const page = await evaluate("location.origin + location.pathname + ' ' + document.title").catch(() => "unavailable");
    assert.fail(`Browser timed out at ${stage} (${page})`);
  }
  async function submit(selector, fields = {}) {
    const button = `document.querySelector(${JSON.stringify(selector)})`;
    await wait(`Boolean(${button})`, selector);
    await evaluate(`(() => {
      const button = ${button};
      for (const [name, value] of Object.entries(${JSON.stringify(fields)})) {
        button.form.elements.namedItem(name).value = value;
      }
      setTimeout(() => button.click(), 0);
      return true;
    })()`);
  }
  async function pdsConsent(pdsOrigin, handle, password, did) {
    const atPds = `location.origin === ${JSON.stringify(pdsOrigin)}`;
    let arrived = await wait(`${atPds} && (
      document.querySelector('form[action="/oauth/authorize/select"]') ? "select" :
      document.querySelector('input[name="password"]') ? "sign-in" :
      document.querySelector('button[value="allow"]') ? "consent" : false)`, "PDS OAuth authorization");
    if (arrived === "select") {
      const accounts = 'form[action="/oauth/authorize/select"]';
      const desired = did ? `${accounts}:has(input[name="did"][value="${did}"]) button`
        : `${accounts}:has(input[name="did"][value^="did:"]) button`;
      if (await evaluate(`Boolean(document.querySelector(${JSON.stringify(desired)}))`)) {
        await submit(desired);
      } else {
        await submit(`${accounts}:has(input[name="did"][value=""]) button`);
        arrived = "sign-in";
      }
    }
    if (arrived === "sign-in") {
      await submit('form[action="/oauth/authorize/sign-in"] button[value="sign-in"]', { identifier: handle, password });
    }
    await submit('form[action="/oauth/authorize/consent"] button[value="allow"]');
  }
  return {
    navigate: (url) => command("Page.navigate", { url }),
    close: () => socket.close(),
    evaluate, wait, submit, pdsConsent,
  };
}

const hash = (value) => createHash("sha256").update(value).digest("base64url");

export async function authorizeSetup(browser, pdsOrigin, redirect, handle, password, scope, fetchPds = fetch, rejectedClient) {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", key.publicKey);
  const encode = (object) => Buffer.from(JSON.stringify(object)).toString("base64url");
  async function dpop(url, options, access) {
    let nonce;
    const htu = new URL(url);
    htu.search = "";
    for (let attempt = 0; attempt < 2; attempt++) {
      const input = encode({ typ: "dpop+jwt", alg: "ES256", jwk: { kty, crv, x, y } }) + "." + encode({
        jti: randomUUID(), htm: options.method, htu: htu.href, iat: Math.floor(Date.now() / 1000),
        ...(nonce && { nonce }), ...(access && { ath: hash(access) }),
      });
      const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, Buffer.from(input));
      const response = await fetchPds(url, { ...options, headers: {
        ...options.headers, DPoP: input + "." + Buffer.from(signature).toString("base64url"),
        ...(access && { Authorization: `DPoP ${access}` }),
      } });
      nonce = response.headers.get("DPoP-Nonce");
      if (!nonce || (await response.clone().json().catch(() => null))?.error !== "use_dpop_nonce") return response;
    }
    assert.fail("PDS rejected the explicit DPoP nonce retry");
  }
  const verifier = randomUUID() + randomUUID();
  const state = randomUUID();
  const client = rejectedClient ?? ("http://localhost?" + new URLSearchParams({ scope, redirect_uri: redirect }));
  const form = (path, body) => dpop(pdsOrigin + path, { method: "POST", body: new URLSearchParams(body) });
  const par = await form("/oauth/par", {
    client_id: client, response_type: "code", redirect_uri: redirect, scope, state,
    code_challenge: hash(verifier), code_challenge_method: "S256",
  });
  if (rejectedClient) {
    assert.equal(par.status, 400);
    const rejected = await par.json();
    assert.equal(rejected.error, "invalid_request");
    assert.match(rejected.error_description, /^Invalid redirect_uri /);
    return;
  }
  assert.equal(par.status, 201, await par.clone().text());
  const { request_uri } = await par.json();
  await browser.navigate(pdsOrigin + "/oauth/authorize?" + new URLSearchParams({ client_id: client, request_uri }));
  await browser.pdsConsent(pdsOrigin, handle, password);
  const callback = new URL(await browser.wait(
    `location.href.startsWith(${JSON.stringify(redirect + "?")}) && location.href`, "setup callback",
  ));
  assert.equal(callback.searchParams.get("state"), state);
  assert.equal(callback.searchParams.get("iss"), pdsOrigin);
  const exchanged = await form("/oauth/token", {
    client_id: client, grant_type: "authorization_code", code: callback.searchParams.get("code"), redirect_uri: redirect,
    code_verifier: verifier,
  });
  if (!exchanged.ok) assert.fail("Setup token exchange failed: " + await exchanged.text());
  const { access_token } = await exchanged.json();
  return (nsid, body) => dpop(pdsOrigin + "/xrpc/" + nsid, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  }, access_token);
}
