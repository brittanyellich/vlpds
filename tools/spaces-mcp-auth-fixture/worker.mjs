import { OAuthAuthorizationServer, OAuthResourceServer } from "./provider.mjs";

import { DurableObject } from "cloudflare:workers";

// The loopback package gives each preview its own disposable issuer database.
export class PreviewIssuerStorage extends DurableObject {
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
    await this.ctx.storage.delete(key);
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
const consent = new Map();
const enrollments = new Map();
const consentLifetime = 120_000;

function escapeHtml(value) {
  const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value).replace(/[&<>"']/g, (character) => entities[character]);
}

function consentPage(authorizationUrl, auth, verified, enrollmentOrigin) {
  const now = Date.now();
  for (const [id, entry] of consent) if (entry.expires <= now) consent.delete(id);
  if (consent.size >= 32) return new Response(null, { status: 503 });
  const id = crypto.randomUUID();
  consent.set(id, { authorizationUrl, verified, expires: now + consentLifetime });
  // Browsers apply form-action to redirects too. The provider has already
  // validated the client callback against its registration.
  const next = verified && new URL(enrollmentOrigin ?? auth.redirectUri);
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
      <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
      <button>Sign in</button>`}
    </form>`, { headers: {
      "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
      "Content-Security-Policy": `default-src 'none'; form-action 'self'${formAction}; frame-ancestors 'none'; base-uri 'none'`,
      "Referrer-Policy": "origin",
    } });
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
  async fetch(request, { ORIGIN: origin, SPACES, SPACES_URL, BINDINGS, BRIDGE_TOKEN, SIGNER, ISSUER_STORAGE, OWNER_PDS, OWNER_PDS_ORIGIN, PREVIEW_MODE, FIXTURE_TESTS, ENROLLMENT_RELAY }, ctx) {
    const url = new URL(request.url);
    const isolated = PREVIEW_MODE === "isolated";
    const fixture = FIXTURE_TESTS === "true" && url.hostname === "127.0.0.1";
    if ((!isolated && !fixture) || (isolated && (
      !BRIDGE_TOKEN || !SIGNER || !OWNER_PDS || !OWNER_PDS_ORIGIN || !SPACES || !SPACES_URL || !BINDINGS
      || !isHttpsOrigin(origin)
    ))) return new Response(null, { status: 503 });
    const browserApproval = BRIDGE_TOKEN && url.pathname === "/authorize" && request.method === "POST";
    const enrollmentRelay = isolated && ENROLLMENT_RELAY === "true";
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
    const env = { OAUTH_KV: ISSUER_STORAGE.getByName("preview-issuer") };
    const api = issuer.getOAuthApi(env);
    const targetsMcp = (auth) => auth.resource === mcp
      || (Array.isArray(auth.resource) && auth.resource.length === 1 && auth.resource[0] === mcp);

    const recordGrant = (operation, ownerSession, evidence) => SPACES.fetch(new URL("/internal/agent-grant-recovery", SPACES_URL), {
      method: "POST",
      headers: { Authorization: `Bearer ${BRIDGE_TOKEN}`, "Content-Type": "application/json",
        "X-Vlpds-Owner-Session": ownerSession },
      body: JSON.stringify({ operation, ...evidence }),
    });
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
      const pending = enrollments.get(state);
      enrollments.delete(state);
      if (!pending || pending.expires <= Date.now()) return new Response(null, { status: 400 });
      const finished = await recordGrant("enrollment-finish", pending.verified.ownerSession, {
        state, code, issuer: OWNER_PDS_ORIGIN,
      });
      if (finished.status !== 204) return new Response(null, { status: 403 });
      const auth = await api.parseAuthRequest(new Request(pending.authorizationUrl));
      return consentPage(pending.authorizationUrl, auth, { ...pending.verified, enrolled: true });
    }
    if (url.pathname === "/authorize" || (fixture && url.pathname === "/fixture/revoke")) {
      let ownerSession = fixture ? request.headers.get("X-Fixture-Owner-Session") : null;
      let approvedBinding;
      let authorizationRequest = request;
      if (BRIDGE_TOKEN && url.pathname === "/authorize") {
        if (request.method === "GET") {
          const auth = await api.parseAuthRequest(request);
          if (!fixture && !targetsMcp(auth)) return new Response(null, { status: 400 });
          return consentPage(request.url, auth);
        }
        if (!browserApproval) return new Response(null, { status: 405 });
        if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded")) {
          return new Response(null, { status: 415 });
        }
        const form = await request.formData();
        const id = form.get("consent");
        const pending = consent.get(id);
        consent.delete(id);
        if (!pending || pending.expires <= Date.now()) return new Response(null, { status: 400 });
        authorizationRequest = new Request(pending.authorizationUrl);
        if (pending.verified) {
          ownerSession = pending.verified.ownerSession;
          approvedBinding = pending.verified;
          if (enrollmentRelay && !approvedBinding.enrolled) {
            const now = Date.now();
            for (const [state, entry] of enrollments) if (entry.expires <= now) enrollments.delete(state);
            if (enrollments.size >= 32) return new Response(null, { status: 503 });
            const started = await recordGrant("enrollment-start", ownerSession);
            if (!started.ok) return new Response(null, { status: 403 });
            const { state, authorizationUrl } = await started.json();
            const target = new URL(authorizationUrl);
            if (typeof state !== "string" || !state || target.origin !== OWNER_PDS_ORIGIN ||
                target.pathname !== "/oauth/authorize") return new Response(null, { status: 503 });
            enrollments.set(state, { ...pending, expires: now + consentLifetime });
            return new Response(null, { status: 303, headers: {
              Location: target.href, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            } });
          }
        } else {
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
          const identity = await recordGrant("owner", ownerSession);
          if (!identity.ok) return new Response(null, { status: 401 });
          const { did, binding } = await identity.json();
          if (!binding?.agent || !binding?.space) return new Response(null, { status: 403 });
          const auth = await api.parseAuthRequest(authorizationRequest);
          return consentPage(pending.authorizationUrl, auth, { did, binding, ownerSession },
            enrollmentRelay ? new URL(OWNER_PDS_ORIGIN).origin : undefined);
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
          evidence = { approval, clientId: auth.clientId, correlation };
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
