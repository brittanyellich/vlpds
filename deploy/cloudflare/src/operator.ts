import { oauthFetch } from './oauth-fetch.ts';
import { OAuthClient, type InternalStateData } from '@atproto/oauth-client';
import { JoseKey } from '@atproto/jwk-jose';
type SavedState = Omit<InternalStateData, 'dpopKey'> & {dpopJwk: NonNullable<JoseKey['privateJwk']>};

export interface OperatorConfig { ADMIN_HOST: string; OPERATOR_DID: string; ADMIN_TOKEN: string }
const LOGIN = '__Host-crate-login';
const SESSION = '__Host-crate-operator';
const TEN_MINUTES = 600_000;
const EIGHT_HOURS = 28_800_000;
const random = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), x => x.toString(16).padStart(2, '0')).join('');
const cookie = (name: string, value: string, seconds: number) => `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${seconds}`;
export function readCookie(request: Request, name: string): string | undefined {
  const matches = (request.headers.get('cookie') ?? '').split(';').map(x => x.trim()).filter(x => x.startsWith(`${name}=`));
  if (matches.length !== 1) return undefined;
  const value = matches[0].slice(name.length + 1);
  return /^[a-f0-9]{64}$/.test(value) ? value : undefined;
}
export function sameOrigin(request: Request, host: string): boolean {
  return request.headers.get('origin') === `https://${host}` &&
    (!request.headers.has('sec-fetch-site') || request.headers.get('sec-fetch-site') === 'same-origin');
}
export function operatorPath(url: URL, host: string): boolean {
  return url.protocol === 'https:' && !url.port && url.hostname === host &&
    !url.pathname.includes('%') && !url.pathname.includes('\\') &&
    (url.pathname === '/' || url.pathname === '/admin' || url.pathname.startsWith('/admin/') ||
     url.pathname.startsWith('/assets/') || url.pathname.startsWith('/xrpc/vlpds.admin.') ||
     ['/favicon.svg', '/operator/login', '/operator/callback', '/operator/logout', '/operator/client-metadata.json'].includes(url.pathname));
}
export function secure(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set('cache-control', 'no-store');
  headers.set('referrer-policy', 'no-referrer');
  headers.set('x-content-type-options', 'nosniff');
  headers.set('x-frame-options', 'DENY');
  for (const key of [...headers.keys()]) if (key.startsWith('access-control-')) headers.delete(key);
  return new Response(response.body, { status: response.status, headers });
}
function page(message = 'Sign in to the operator console'): Response {
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>crate.social operator</title><body><main><h1>${message}</h1><p>Only the authorized Atmosphere account can administer this PDS.</p><form method="post" action="/operator/login"><button>Sign in with Atmosphere</button></form></main></body></html>`, { headers: {'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"} });
}
interface Expiring<T> { value: T; expires: number }
export class OperatorGateway {
  private client: OAuthClient;
  private storage: DurableObjectStorage;
  private config: OperatorConfig;
  constructor(storage: DurableObjectStorage, config: OperatorConfig) {
    this.storage = storage;
    this.config = config;
    this.client = new OAuthClient({
      responseMode: 'query',
      runtimeImplementation: {
        createKey: algs => JoseKey.generate(algs),
        getRandomValues: length => crypto.getRandomValues(new Uint8Array(length)),
        digest: async (bytes, alg) => new Uint8Array(await crypto.subtle.digest(alg.name.replace("sha", "SHA-"), bytes)),
        // No refresh operations: each callback has a separately consumed browser flow.
        requestLock: async (_key, fn) => fn(),
      },
      clientMetadata: this.metadata(),
      fetch: oauthFetch,
      // Login is pinned to a DID, never arbitrary user-controlled discovery.
      handleResolver: 'https://bsky.social',
      stateStore: {
        get: async key => {
          const saved = await this.get<SavedState>(`oauth:${key}`);
          if (!saved) return;
          const {dpopJwk, ...rest} = saved;
          return {...rest, dpopKey:await JoseKey.fromJWK(dpopJwk)};
        },
        set: async (key, {dpopKey, ...rest}) => {
          if (!dpopKey.privateJwk) throw new Error('Missing DPoP key');
          await storage.put(`oauth:${key}`, {value:{...rest,dpopJwk:dpopKey.privateJwk}, expires: Date.now() + TEN_MINUTES});
        },
        del: async key => { await storage.delete(`oauth:${key}`); },
      },
      // We use OAuth only to establish identity. Do not retain account access tokens.
      sessionStore: { get: async () => undefined, set: async () => {}, del: async () => {} },
    });
  }
  metadata() {
    const origin = `https://${this.config.ADMIN_HOST}`;
    return { client_id: `${origin}/operator/client-metadata.json`, client_name: 'crate.social operator console',
      client_uri: origin, redirect_uris: [`${origin}/operator/callback`] as [string],
      scope: 'atproto', grant_types: ['authorization_code'] as ['authorization_code'], response_types: ['code'] as ['code'],
      token_endpoint_auth_method: 'none' as const, application_type: 'web' as const, dpop_bound_access_tokens: true };
  }
  private async get<T>(key: string): Promise<T | undefined> {
    const item = await this.storage.get<Expiring<T>>(key);
    if (!item) return;
    if (item.expires <= Date.now()) { await this.storage.delete(key); return; }
    return item.value;
  }
  async cleanup(): Promise<void> {
    for (const prefix of ['oauth:', 'login:', 'session:']) {
      const items = await this.storage.list<Expiring<unknown>>({prefix, limit: 1000});
      const expired = [...items].filter(([, v]) => v.expires <= Date.now()).map(([k]) => k);
      if (expired.length) await this.storage.delete(expired);
    }
  }
  async handle(request: Request, upstream: (request: Request) => Promise<Response>): Promise<Response> {
    const url = new URL(request.url);
    if (!operatorPath(url, this.config.ADMIN_HOST)) return new Response('Not found', {status:404});
    const path = url.pathname;
    if (path === '/operator/client-metadata.json' && request.method === 'GET') return Response.json(this.metadata());
    if (path === '/operator/login' && request.method === 'POST') {
      if (!sameOrigin(request, this.config.ADMIN_HOST)) return new Response('Forbidden', {status:403});
      // Bound outstanding requests per server to avoid unauthenticated state exhaustion.
      const rateAllowed = await this.storage.transaction(async tx => {
        const recent = await tx.get<number>('operator:last-login') ?? 0;
        if (Date.now() - recent < 5000) return false;
        await tx.put('operator:last-login', Date.now());
        return true;
      });
      if (!rateAllowed) return new Response('Try again shortly', {status:429});
      const nonce = random();
      const redirect = await this.client.authorize(this.config.OPERATOR_DID, {state: nonce, scope:'atproto'});
      // PAR authorization URLs may contain only request_uri; associate using SDK application state on callback.
      await this.storage.put(`login:${nonce}`, {value: true, expires: Date.now() + TEN_MINUTES});
      return new Response(null, {status:303, headers:{location:redirect.href, 'set-cookie':cookie(LOGIN,nonce,600)}});
    }
    if (path === '/operator/callback' && request.method === 'GET') {
      const nonce = readCookie(request, LOGIN);
      if (!nonce || url.search.length > 8192) return new Response('Login expired. Start again.', {status:400});
      // Consume before awaiting external calls so a browser flow can be used only once.
      const allowed = await this.storage.transaction(async tx => {
        const item = await tx.get<Expiring<boolean>>(`login:${nonce}`);
        await tx.delete(`login:${nonce}`);
        return item && item.expires > Date.now();
      });
      if (!allowed) return new Response('Login expired. Start again.', {status:400});
      const result = await this.client.callback(url.searchParams);
      if (result.state !== nonce || result.session.did !== this.config.OPERATOR_DID) return new Response('Not an authorized operator', {status:403});
      const session = random();
      await this.storage.put(`session:${session}`, {value:result.session.did, expires:Date.now()+EIGHT_HOURS});
      const headers = new Headers({location:'/admin'});
      headers.append('set-cookie',cookie(SESSION,session,EIGHT_HOURS/1000));
      headers.append('set-cookie',cookie(LOGIN,'',0));
      return new Response(null, {status:303,headers});
    }
    const session = readCookie(request, SESSION);
    const did = session ? await this.get<string>(`session:${session}`) : undefined;
    if (path === '/operator/logout' && request.method === 'POST') {
      if (!sameOrigin(request,this.config.ADMIN_HOST)) return new Response('Forbidden',{status:403});
      if (session) await this.storage.delete(`session:${session}`);
      return new Response(null,{status:303,headers:{location:'/', 'set-cookie':cookie(SESSION,'',0)}});
    }
    if (did !== this.config.OPERATOR_DID) return path.startsWith('/xrpc/') ? new Response('Sign in required',{status:401}) : page();
    if (path.startsWith('/operator/')) return new Response('Not found',{status:404});
    // All API calls (including reads) require a same-origin browser request.
    if (path.startsWith('/xrpc/') && request.headers.get('sec-fetch-site') !== 'same-origin') return new Response('Forbidden',{status:403});
    if (!['GET','HEAD'].includes(request.method) && !sameOrigin(request,this.config.ADMIN_HOST)) return new Response('Forbidden',{status:403});
    if (path === '/') return new Response(`<!doctype html><title>Operator session</title><a href="/admin">Open console</a><form method="post" action="/operator/logout"><button>Sign out</button></form>`,{headers:{'content-type':'text/html; charset=utf-8'}});
    if (path === '/xrpc/vlpds.admin.getSession') return Response.json({auth:'proxy',operator:did});
    // The gateway authenticates the browser; the container credential never reaches it.
    const headers = new Headers(request.headers);
    headers.delete('cookie');
    headers.set('authorization', `Basic ${btoa(`admin:${this.config.ADMIN_TOKEN}`)}`);
    return upstream(new Request(request,{headers}));
  }
}
