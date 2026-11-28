import { OAuthAuthorizationServer, OAuthResourceServer } from "./provider.mjs";

import { DurableObject } from "cloudflare:workers";

// The loopback package gives each preview its own disposable issuer database.
export class PreviewIssuerStorage extends DurableObject {
  async putConsent(phase, id, sealed) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const now = Date.now();
      const storage = this.ctx.storage;
      const prefix = consentPrefix(phase);
      const rows = await storage.list({ prefix, limit: 32 });
      const expired = [...rows].filter(([, row]) => row.expires <= now).map(([key]) => key);
      if (expired.length) await storage.delete(expired);
      const key = prefix + id;
      if (rows.size - expired.length >= 32 || (rows.has(key) && !expired.includes(key))) return false;
      const expires = now + consentLifetime;
      const alarm = await storage.getAlarm();
      if (alarm === null || alarm > expires) await storage.setAlarm(expires);
      await storage.put(key, { sealed, expires });
      return true;
    });
  }

  async alarm() {
    await this.ctx.blockConcurrencyWhile(async () => {
      const storage = this.ctx.storage;
      const now = Date.now();
      const rows = await storage.list({ prefix: browserPrefix });
      const expired = [...rows].filter(([, row]) => row.expires <= now).map(([key]) => key);
      if (expired.length) await storage.delete(expired);
      const next = Math.min(...[...rows.values()].filter((row) => row.expires > now).map((row) => row.expires));
      if (Number.isFinite(next)) await this.schedule(next);
    });
    await this.flushRevocations();
  }

  async takeConsent(phase, id) {
    const key = consentPrefix(phase) + id;
    return this.ctx.storage.transaction(async (tx) => {
      const row = await tx.get(key);
      if (!row) return null;
      await tx.delete(key);
      return row.expires > Date.now() ? row.sealed : null;
    });
  }

  async get(key, options) {
    const row = await this.ctx.storage.get(key);
    if (!row || row.expires <= Date.now()) return null;
    return (typeof options === "string" ? options : options?.type) === "json"
      ? JSON.parse(row.value) : row.value;
  }

  async put(key, value, options) {
    const expires = options?.expirationTtl ? Date.now() + options.expirationTtl * 1000 : Infinity;
    await this.ctx.storage.put(key, { value, metadata: options?.metadata, expires });
  }

  async delete(key) {
    const storage = this.ctx.storage;
    if (!this.env.BRIDGE_TOKEN || !key.startsWith("grant:")) {
      await storage.delete(key);
      return;
    }
    await this.ctx.blockConcurrencyWhile(async () => {
      const row = await storage.get(key);
      const facts = row && revocationEvidence(key, JSON.parse(row.value), this.env.ORIGIN, this.env.BINDINGS);
      if (!facts) {
        await storage.delete(key);
        return;
      }
      await this.schedule(Date.now() + 1000);
      await storage.transaction(async (tx) => {
        await tx.put(revocationPrefix + key, facts);
        await tx.delete(key);
      });
    });
  }

  async schedule(when) {
    const alarm = await this.ctx.storage.getAlarm();
    if (alarm === null || alarm > when) await this.ctx.storage.setAlarm(when);
  }

  async flushRevocations() {
    const storage = this.ctx.storage;
    const rows = await storage.list({ prefix: revocationPrefix, limit: 16 });
    for (const [key, evidence] of rows) {
      try {
        const result = await this.env.SPACES.fetch(new URL("/internal/agent-grant-recovery", this.env.SPACES_URL), {
          method: "POST", redirect: "manual", signal: AbortSignal.timeout(3000),
          headers: { Authorization: `Bearer ${this.env.BRIDGE_TOKEN}`, "Content-Type": "application/json" },
          body: JSON.stringify({ operation: "issuer-revoked", ...evidence }),
        });
        if (result.status === 204) await storage.delete(key);
      } catch {
        // Keep authoritative issuer evidence for the next attempt.
      }
    }
    if ((await storage.list({ prefix: revocationPrefix, limit: 1 })).size) await this.schedule(Date.now() + 10000);
  }

  async list({ prefix = "", cursor, limit = 1000 } = {}) {
    const rows = await this.ctx.storage.list({ prefix, startAfter: cursor });
    const now = Date.now();
    const keys = [...rows].filter(([, row]) => row.expires > now)
      .map(([name, row]) => ({ name, metadata: row.metadata }));
    const page = keys.slice(0, limit);
    return keys.length > page.length
      ? { keys: page, list_complete: false, cursor: page.at(-1).name }
      : { keys: page, list_complete: true };
  }
}

// Fixed, synthetic sessions stand in for completed owner authentication and consent.
// They are fixture inputs delivered over loopback exclusively.
const owners = new Map([
  ["owner-a-session", { userId: "owner-a", binding: "a-chat" }],
  ["owner-b-session", { userId: "owner-b", binding: "b-chat" }],
]);
const scope = "mcp:chat";
const consentLifetime = 120_000;
const browserPrefix = "exp711:browser:";
const consentPrefix = (phase) => `${browserPrefix}${phase}:`;
const validConsentId = (id) => typeof id === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(id);

// The Worker seals the full owner session before passing it to shared storage.
function browserState(storage, bridgeToken, origin) {
  let key;
  async function encryptionKey() {
    if (!key) {
      const input = await crypto.subtle.importKey("raw", encoder.encode(bridgeToken), "HKDF", false, ["deriveKey"]);
      key = await crypto.subtle.deriveKey({
        name: "HKDF", hash: "SHA-256", salt: encoder.encode(origin), info: encoder.encode("exp711 browser consent v1"),
      }, input, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }
    return key;
  }
  const params = (phase, id, iv) => ({ name: "AES-GCM", iv, additionalData: encoder.encode(consentPrefix(phase) + id) });
  return {
    async put(phase, id, pending) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const cipher = await crypto.subtle.encrypt(params(phase, id, iv), await encryptionKey(),
        encoder.encode(JSON.stringify(pending)));
      return storage.putConsent(phase, id, { iv, cipher });
    },
    async take(phase, id) {
      if (!validConsentId(id)) return null;
      const sealed = await storage.takeConsent(phase, id);
      if (!sealed) return null;
      try {
        const clear = await crypto.subtle.decrypt(params(phase, id, sealed.iv), await encryptionKey(), sealed.cipher);
        return JSON.parse(new TextDecoder().decode(clear));
      } catch {
        return null;
      }
    },
  };
}

function escapeHtml(value) {
  const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value).replace(/[&<>"']/g, (character) => entities[character]);
}

async function consentPage(store, authorizationUrl, auth, verified, enrollmentOrigin, nativeSignIn = false) {
  const id = crypto.randomUUID();
  if (!await store.put("consent", id, { authorizationUrl, verified })) return new Response(null, { status: 503 });
  // Browsers apply form-action to redirects too. The provider has already
  // validated the client callback against its registration.
  const next = enrollmentOrigin ? new URL(enrollmentOrigin) : verified && new URL(auth.redirectUri);
  const formAction = next && ["https:", "http:"].includes(next.protocol) ? " " + next.origin : "";
  return new Response(`<!doctype html><meta charset="utf-8">
    <title>Approve disposable Spaces chat</title>
    <h1>Approve disposable Spaces chat</h1>
    ${verified ? `<p>Owner <code>${escapeHtml(verified.did)}</code></p>
    <p>Agent <code>${escapeHtml(verified.binding.agent)}</code></p>
    <p>Space <code>${escapeHtml(verified.binding.space)}</code></p>`
    : "<p>Sign in with a disposable PDS owner account to review the requested access.</p>"}
    <p>Client <code>${escapeHtml(auth.clientId)}</code></p>
    <p>Resource <code>${escapeHtml(auth.resource)}</code></p>
    <form action="/authorize" method="post">
      <input type="hidden" name="consent" value="${id}">
      ${verified ? '<button>Approve access</button>' : `<label>Owner handle <input name="handle" autocomplete="username" required></label>
      ${nativeSignIn ? "" : '<label>Password <input name="password" type="password" autocomplete="current-password" required></label>'}
      <button>Sign in</button>`}
    </form>`, { headers: {
      "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
      "Content-Security-Policy": `default-src 'none'; form-action 'self'${formAction}; frame-ancestors 'none'; base-uri 'none'`,
      "Referrer-Policy": "origin",
    } });
}


const revocationPrefix = "exp711:revocation:";

function revocationEvidence(key, grant, origin, bindings) {
  const { id, userId, clientId, metadata, resource } = grant;
  if (resource !== origin + "/mcp" || key !== `grant:${userId}:${id}` || !metadata) return null;
  const owner = metadata.ownerDid ?? JSON.parse(bindings)[userId]?.ownerDid;
  if (typeof owner !== "string" || base64url(encoder.encode(owner)) !== userId ||
      metadata.clientId !== clientId || !metadata.approval || !metadata.correlation) return null;
  return { owner, approval: metadata.approval, clientId, correlation: metadata.correlation, grantId: id };
}

const encoder = new TextEncoder();
const base64url = (bytes) => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

async function signDispatch(signer, issuer, resource, owner, grant, body) {
  const key = await crypto.subtle.importKey("jwk", signer.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: signer.iss, aud: signer.aud, lxm: signer.method,
    iat: now, exp: now + 25, jti: hex(crypto.getRandomValues(new Uint8Array(16))),
    issuer, resource, owner, grant,
    body_sha256: hex(new Uint8Array(await crypto.subtle.digest("SHA-256", body))),
  };
  const header = base64url(encoder.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const payload = base64url(encoder.encode(JSON.stringify(claims)));
  const input = header + "." + payload;
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, encoder.encode(input));
  return input + "." + base64url(new Uint8Array(signature));
}

function isHttpsOrigin(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin === value;
  } catch {
    return false;
  }
}

export default {
  async fetch(request, { ORIGIN: origin, SPACES, SPACES_URL, BINDINGS, BRIDGE_TOKEN, SIGNER, ISSUER_STORAGE, OWNER_PDS, OWNER_PDS_ORIGIN, PREVIEW_MODE, FIXTURE_TESTS, ENROLLMENT_RELAY, ATPROTO_SIGN_IN }, ctx) {
    const url = new URL(request.url);
    const isolated = PREVIEW_MODE === "isolated";
    const fixture = FIXTURE_TESTS === "true" && url.hostname === "127.0.0.1";
    if ((!isolated && !fixture) || (isolated && (
      !BRIDGE_TOKEN || !SIGNER || !OWNER_PDS || !OWNER_PDS_ORIGIN || !SPACES || !SPACES_URL || !BINDINGS
      || !isHttpsOrigin(origin)
    ))) return new Response(null, { status: 503 });
    const browserApproval = BRIDGE_TOKEN && url.pathname === "/authorize" && request.method === "POST";
    const enrollmentRelay = isolated && ENROLLMENT_RELAY === "true";
    const nativeSignIn = enrollmentRelay && ATPROTO_SIGN_IN === "true";
    const callback = enrollmentRelay && url.pathname === "/spaces-callback";
    const expectedOrigin = callback ? OWNER_PDS_ORIGIN : browserApproval ? origin : null;
    if (url.origin !== origin || request.headers.get("Origin") !== expectedOrigin ||
        ((browserApproval || callback) && url.search)) {
      return new Response(null, { status: 403 });
    }
    const mcp = origin + "/mcp";
    const other = origin + "/other";
    const issuer = new OAuthAuthorizationServer({
      issuer: origin,
      resources: fixture ? [mcp, other] : [mcp],
      clientRegistrationEndpoint: "/register",
      scopesSupported: [scope, "offline_access"],
    });
    const store = browserState(ISSUER_STORAGE.getByName("preview-browser"), BRIDGE_TOKEN, origin);
    const env = { OAUTH_KV: ISSUER_STORAGE.getByName("preview-issuer") };
    const api = issuer.getOAuthApi(env);
    const targetsMcp = (auth) => auth.resource === mcp
      || (Array.isArray(auth.resource) && auth.resource.length === 1 && auth.resource[0] === mcp);

    const recordGrant = (operation, ownerSession, evidence) => SPACES.fetch(new URL("/internal/agent-grant-recovery", SPACES_URL), {
      method: "POST",
      headers: { Authorization: `Bearer ${BRIDGE_TOKEN}`, "Content-Type": "application/json",
        ...(ownerSession && { "X-Vlpds-Owner-Session": ownerSession }) },
      body: JSON.stringify({ operation, ...evidence }),
    });
    function authorizationTarget(url) {
      const target = new URL(url);
      if (target.origin !== OWNER_PDS_ORIGIN || target.pathname !== "/oauth/authorize") return null;
      return target.href;
    }
    const authorizeRedirect = (target) => new Response(null, { status: 303, headers: {
      Location: target, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
    } });
    async function ownerReview(authorizationUrl, ownerSession) {
      const identity = await recordGrant("owner", ownerSession);
      if (!identity.ok) return new Response(null, { status: 401 });
      const { did, binding } = await identity.json();
      if (!binding?.agent || !binding?.space) return new Response(null, { status: 403 });
      const auth = await api.parseAuthRequest(new Request(authorizationUrl));
      let enrolled = false;
      if (nativeSignIn) {
        const status = await recordGrant("enrollment-status", ownerSession);
        if (!status.ok) return new Response(null, { status: 403 });
        enrolled = (await status.json()).enrolled === true;
      }
      return consentPage(store, authorizationUrl, auth, { did, binding, ownerSession, enrolled },
        enrollmentRelay && !enrolled ? new URL(OWNER_PDS_ORIGIN).origin : undefined);
    }
    if (callback) {
      if (request.method !== "POST") return new Response(null, { status: 405 });
      if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded")) {
        return new Response(null, { status: 403 });
      }
      const form = await request.formData();
      const state = form.get("state");
      const code = form.get("code");
      if (typeof state !== "string" || typeof code !== "string" || !code || code.length > 512 ||
          form.get("issuer") !== OWNER_PDS_ORIGIN) return new Response(null, { status: 400 });
      if (nativeSignIn && state.startsWith("login-")) {
        const pending = await store.take("login", state);
        if (!pending) return new Response(null, { status: 400 });
        const finished = await recordGrant("login-finish", null, {
          state, code, issuer: OWNER_PDS_ORIGIN, context: pending.context,
        });
        if (!finished.ok) return new Response(null, { status: 403 });
        const { session } = await finished.json();
        if (typeof session !== "string" || !session) return new Response(null, { status: 403 });
        return ownerReview(pending.authorizationUrl, `Preview ${session}`);
      }
      const pending = await store.take("enrollment", state);
      if (!pending) return new Response(null, { status: 400 });
      const finished = await recordGrant("enrollment-finish", pending.verified.ownerSession, {
        state, code, issuer: OWNER_PDS_ORIGIN,
      });
      if (finished.status !== 204) return new Response(null, { status: 403 });
      const auth = await api.parseAuthRequest(new Request(pending.authorizationUrl));
      return consentPage(store, pending.authorizationUrl, auth, { ...pending.verified, enrolled: true });
    }
    if (url.pathname === "/authorize" || (fixture && url.pathname === "/fixture/revoke")) {
      let ownerSession = fixture ? request.headers.get("X-Fixture-Owner-Session") : null;
      let approvedBinding;
      let authorizationRequest = request;
      if (BRIDGE_TOKEN && url.pathname === "/authorize") {
        if (request.method === "GET") {
          const auth = await api.parseAuthRequest(request);
          if (!fixture && !targetsMcp(auth)) return new Response(null, { status: 400 });
          return consentPage(store, request.url, auth, undefined, nativeSignIn ? new URL(OWNER_PDS_ORIGIN).origin : undefined, nativeSignIn);
        }
        if (!browserApproval) return new Response(null, { status: 405 });
        if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded")) {
          return new Response(null, { status: 415 });
        }
        const form = await request.formData();
        const id = form.get("consent");
        const pending = await store.take("consent", id);
        if (!pending) return new Response(null, { status: 400 });
        authorizationRequest = new Request(pending.authorizationUrl);
        if (pending.verified) {
          ownerSession = pending.verified.ownerSession;
          approvedBinding = pending.verified;
          if (enrollmentRelay && !approvedBinding.enrolled) {
            const started = await recordGrant("enrollment-start", ownerSession);
            if (!started.ok) return new Response(null, { status: 403 });
            const { state, authorizationUrl } = await started.json();
            const target = authorizationTarget(authorizationUrl);
            if (!validConsentId(state) || !target) return new Response(null, { status: 503 });
            if (!await store.put("enrollment", state, pending)) return new Response(null, { status: 503 });
            return authorizeRedirect(target);
          }
        } else {
          if (nativeSignIn) {
            const handle = form.get("handle");
            if (typeof handle !== "string" || !handle || handle.length > 253) return new Response(null, { status: 400 });
            const started = await recordGrant("login-start", null, { handle });
            if (!started.ok) return new Response(null, { status: 403 });
            const { state, context, authorizationUrl } = await started.json();
            const target = authorizationTarget(authorizationUrl);
            if (!validConsentId(state) || !state.startsWith("login-") || typeof context !== "string" || !context || !target) return new Response(null, { status: 503 });
            if (!await store.put("login", state, { authorizationUrl: pending.authorizationUrl, context })) {
              return new Response(null, { status: 503 });
            }
            return authorizeRedirect(target);
          }
          const login = await OWNER_PDS.fetch(new URL("/xrpc/com.atproto.server.createSession", OWNER_PDS_ORIGIN), {
            method: "POST",
            redirect: "manual",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ identifier: form.get("handle"), password: form.get("password") }),
          });
          if (!login.ok) return new Response(null, { status: 401 });
          const { accessJwt } = await login.json();
          if (typeof accessJwt !== "string" || !accessJwt) return new Response(null, { status: 401 });
          ownerSession = `Bearer ${accessJwt}`;
          return ownerReview(pending.authorizationUrl, ownerSession);
        }
      }
      let owner;
      if (BRIDGE_TOKEN && ownerSession) {
        const identity = await recordGrant("owner", ownerSession);
        if (identity.ok) {
          const { did, binding } = await identity.json();
          if (approvedBinding && (approvedBinding.did !== did || approvedBinding.binding.space !== binding?.space
              || approvedBinding.binding.agent !== binding?.agent)) return new Response(null, { status: 403 });
          // The issuer uses colon-delimited storage keys. Encode the DID
          // losslessly as its issuer subject and retain the DID for dispatch.
          const userId = base64url(encoder.encode(did));
          if (JSON.parse(BINDINGS)[userId]?.ownerDid === did) owner = { userId };
        }
      } else if (!BRIDGE_TOKEN) {
        owner = owners.get(request.headers.get("X-Fixture-Owner"));
      }
      if (!owner) return new Response(null, { status: 401 });

      if (url.pathname === "/fixture/revoke" && request.method === "GET") {
        const { items } = await api.listUserGrants(owner.userId);
        return Response.json(items.map(({ id }) => id));
      }
      if (url.pathname === "/fixture/revoke" && request.method === "POST") {
        const { grantId } = await request.json();
        const { items } = await api.listUserGrants(owner.userId);
        const grant = items.find(({ id }) => id === grantId);
        if (!grant) return new Response(null, { status: 404 });
        if (BRIDGE_TOKEN && grant.resource === mcp) {
          const evidence = { ...grant.metadata, clientId: grant.clientId, grantId };
          const revoked = await recordGrant("revoke", ownerSession, evidence);
          if (!revoked.ok) return new Response(null, { status: 503 });
          await api.revokeGrant(grantId, owner.userId);
          const acknowledged = await recordGrant("issuer-cleaned", ownerSession, evidence);
          return new Response(null, { status: acknowledged.ok ? 204 : 503 });
        }
        await api.revokeGrant(grantId, owner.userId);
        return new Response(null, { status: 204 });
      }
      if (url.pathname === "/authorize" && (browserApproval || request.method === "GET")) {
        const auth = await api.parseAuthRequest(authorizationRequest);
        const granted = auth.scope.filter((requested) => requested === scope || requested === "offline_access");
        const durable = BRIDGE_TOKEN && targetsMcp(auth);
        let evidence;
        if (durable) {
          const canonical = JSON.stringify({ ...auth, scope: [...new Set(auth.scope)].sort(), resource: mcp });
          const approval = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(canonical))));
          const begin = await recordGrant("begin", ownerSession, { approval, clientId: auth.clientId, binding: approvedBinding?.binding });
          if (!begin.ok) return new Response(null, { status: begin.status });
          const { correlation } = await begin.json();
          evidence = { approval, clientId: auth.clientId, correlation, ownerDid: approvedBinding?.did };
        }
        const { redirectTo } = await api.completeAuthorization({
          request: auth,
          userId: owner.userId,
          metadata: evidence,
          props: owner,
          // The durable adapter must acknowledge revocation separately.
          ...(BRIDGE_TOKEN ? { revokeExistingGrants: false } : {}),
          scope: granted,
        });
        if (durable) {
          const { items } = await api.listUserGrants(owner.userId);
          const grant = items.find(({ metadata, resource, userId, clientId }) =>
            metadata?.correlation === evidence.correlation && resource === mcp &&
            userId === owner.userId && clientId === auth.clientId);
          if (!grant) return new Response(null, { status: 503 });
          const observed = { ...evidence, grantId: grant.id };
          if (fixture && request.headers.get("X-Fixture-Lose-Redirect") === "yes") {
            // The issuer grant exists, but the browser never receives its code.
            return new Response(null, { status: 503 });
          }
          const approved = await recordGrant("approve", ownerSession, observed);
          if (!approved.ok) {
            return new Response(null, { status: 403 });
          }
        }
        return Response.redirect(redirectTo, 303);
      }
      return new Response(null, { status: 405 });
    }
    if (url.pathname === "/mcp" || url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      const endpoint = new OAuthResourceServer({
        resourceMetadata: { resource: mcp, authorization_servers: [origin] },
        requiredScopes: [scope],
        validateToken: () => (audience, token) => issuer.validateToken(audience, token, env),
        handler: {
          async fetch(request, _env, authenticated) {
            if (!authenticated.auth.scope.includes(scope)) return new Response(null, { status: 403 });
            const headers = new Headers();
            let body = request.body;
            let target = SPACES_URL;
            if (SIGNER) {
              if (request.method !== "POST") return new Response(null, { status: 405 });
              const signer = JSON.parse(SIGNER);
              // validateToken has already verified the resource, expiry and
              // scope. unwrapToken exposes the library's stable grant ID.
              const verified = await api.unwrapToken(authenticated.auth.token);
              if (!verified || verified.userId !== authenticated.auth.userId || !verified.grantId
                  || authenticated.auth.audience !== mcp) return new Response(null, { status: 401 });
              const binding = JSON.parse(BINDINGS)[verified.userId];
              if (!binding) return new Response(null, { status: 403 });
              body = await request.arrayBuffer();
              if (body.byteLength > 64 * 1024) return new Response(null, { status: 413 });
              const assertion = await signDispatch(signer, origin, mcp, binding.ownerDid, verified.grantId, body);
              headers.set("Authorization", `Bearer ${assertion}`);
              target = new URL("/xrpc/" + signer.method, SPACES_URL);
            } else {
              const binding = JSON.parse(BINDINGS)[authenticated.props.binding];
              if (!binding) return new Response(null, { status: 403 });
              headers.set("Authorization", `Bearer ${binding.token}`);
            }
            // Only allowlisted protocol headers cross the private hop.
            for (const name of ["Accept", "Content-Type", "MCP-Protocol-Version"]) {
              const value = request.headers.get(name);
              if (value !== null) headers.set(name, value);
            }
            return SPACES.fetch(target, {
              method: request.method,
              headers,
              body,
              redirect: "manual",
            });
          },
        },
      });
      return endpoint.fetch(request, env, ctx);
    }
    return issuer.fetch(request, env, ctx);
  },
};
