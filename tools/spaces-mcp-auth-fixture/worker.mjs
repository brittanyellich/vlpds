import { OAuthAuthorizationServer, OAuthResourceServer } from "./provider.mjs";

// Disposable single-isolate storage. Production revocation consistency is a separate decision.
const rows = new Map();
const env = {
  OAUTH_KV: {
    async get(key, options) {
      const row = rows.get(key);
      if (!row) return null;
      return options?.type === "json" ? JSON.parse(row.value) : row.value;
    },
    async put(key, value, options) {
      rows.set(key, { value, metadata: options?.metadata });
    },
    async delete(key) {
      rows.delete(key);
    },
    async list({ prefix = "" } = {}) {
      const keys = [...rows]
        .filter(([key]) => key.startsWith(prefix))
        .map(([name, row]) => ({ name, metadata: row.metadata }));
      return { keys, list_complete: true };
    },
  },
};

// Fixed, synthetic sessions stand in for completed owner authentication and consent.
// They are fixture inputs delivered over loopback exclusively.
const owners = new Map([
  ["owner-a-session", { userId: "owner-a", binding: "a-chat" }],
  ["owner-b-session", { userId: "owner-b", binding: "b-chat" }],
]);
const scope = "mcp:chat";
const consent = new Map();
const consentLifetime = 120_000;

function escapeHtml(value) {
  const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value).replace(/[&<>"']/g, (character) => entities[character]);
}

function consentPage(authorizationUrl, auth) {
  const now = Date.now();
  for (const [id, entry] of consent) if (entry.expires <= now) consent.delete(id);
  if (consent.size >= 32) return new Response(null, { status: 503 });
  const id = crypto.randomUUID();
  consent.set(id, { authorizationUrl, expires: now + consentLifetime });
  return new Response(`<!doctype html><meta charset="utf-8">
    <title>Approve disposable Spaces chat</title>
    <h1>Approve disposable Spaces chat</h1>
    <p>Sign in with a disposable PDS owner account to allow access to its approved private chat Space.</p>
    <p>Client <code>${escapeHtml(auth.clientId)}</code></p>
    <p>Resource <code>${escapeHtml(auth.resource)}</code></p>
    <form action="/authorize" method="post">
      <input type="hidden" name="consent" value="${id}">
      <label>Owner handle <input name="handle" autocomplete="username" required></label>
      <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
      <button>Sign in and approve</button>
    </form>`, { headers: {
      "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      "Referrer-Policy": "no-referrer",
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

export default {
  async fetch(request, { ORIGIN: origin, SPACES, SPACES_URL, BINDINGS, BRIDGE_TOKEN, SIGNER }, ctx) {
    const url = new URL(request.url);
    const browserApproval = BRIDGE_TOKEN && url.pathname === "/authorize" && request.method === "POST";
    if (url.origin !== origin || (browserApproval
      ? request.headers.get("Origin") !== origin || Boolean(url.search)
      : request.headers.has("Origin"))) {
      return new Response(null, { status: 403 });
    }
    const mcp = origin + "/mcp";
    const other = origin + "/other";
    const issuer = new OAuthAuthorizationServer({
      issuer: origin,
      resources: [mcp, other],
      clientRegistrationEndpoint: "/register",
      scopesSupported: [scope, "offline_access"],
    });
    const api = issuer.getOAuthApi(env);
    const recordGrant = (operation, ownerSession, evidence) => SPACES.fetch(new URL("/fixture/grant", SPACES_URL), {
      method: "POST",
      headers: { Authorization: `Bearer ${BRIDGE_TOKEN}`, "Content-Type": "application/json",
        "X-Fixture-Owner-Session": ownerSession },
      body: JSON.stringify({ operation, ...evidence }),
    });
    if (url.pathname === "/authorize" || url.pathname === "/fixture/revoke") {
      let ownerSession = request.headers.get("X-Fixture-Owner-Session");
      let authorizationRequest = request;
      if (BRIDGE_TOKEN && url.pathname === "/authorize") {
        if (request.method === "GET") {
          const auth = await api.parseAuthRequest(request);
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
        const login = await recordGrant("sign-in", "", { handle: form.get("handle"), password: form.get("password") });
        if (!login.ok) return new Response(null, { status: 401 });
        const { session } = await login.json();
        ownerSession = `Bearer ${session}`;
        authorizationRequest = new Request(pending.authorizationUrl);
      }
      let owner;
      if (BRIDGE_TOKEN && ownerSession) {
        const identity = await recordGrant("owner", ownerSession);
        if (identity.ok) {
          const { did } = await identity.json();
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
        const durable = BRIDGE_TOKEN && (auth.resource === mcp || (auth.resource?.length === 1 && auth.resource[0] === mcp));
        let evidence;
        if (durable) {
          const canonical = JSON.stringify({ ...auth, scope: [...new Set(auth.scope)].sort(), resource: mcp });
          const approval = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(canonical))));
          const begin = await recordGrant("begin", ownerSession, { approval, clientId: auth.clientId });
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
          if (request.headers.get("X-Fixture-Lose-Redirect") === "yes") {
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
