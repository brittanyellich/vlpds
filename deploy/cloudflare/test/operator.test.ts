import assert from 'node:assert/strict';
import {test} from 'node:test';
import {OperatorGateway, operatorPath, readCookie, secure} from '../src/operator.ts';
import {validateJsonSize} from '../src/oauth-fetch.ts';
const host = 'admin.example.com';
const did = 'did:plc:4hodhjl2kposuchzvpiviwps';
const nonce = 'a'.repeat(64);
const session = 'b'.repeat(64);
function fixture() {
  const records = new Map();
  const storage = {get:async k => records.get(k), put:async (k,v) => {records.set(k,v)}, delete:async k => {for (const key of Array.isArray(k)?k:[k]) records.delete(key)}, list:async ({prefix}) => new Map([...records].filter(([k]) => k.startsWith(prefix))), transaction:async f => f(storage)};
  const gateway = new OperatorGateway(storage as any, {ADMIN_HOST:host,OPERATOR_DID:did,ADMIN_TOKEN:'never-send-to-browser'});
  const calls: Request[] = [];
  const upstream = async (r:Request) => {calls.push(r); return new Response('upstream');};
  const req = (path:string, init:RequestInit={}) => new Request(`https://${host}${path}`,init);
  return {gateway,records,calls,upstream,req};
}
test('admin routing excludes public, internal, encoded and insecure URLs', () => {
  for (const p of ['/admin','/assets/app.js','/xrpc/vlpds.admin.getClusterStatus']) assert(operatorPath(new URL(`https://${host}${p}`),host));
  for (const u of [`http://${host}/admin`,`https://evil.example/admin`,`https://${host}/internal`,`https://${host}/xrpc/vlpds.internal.forward`,`https://${host}/%61dmin`]) assert(!operatorPath(new URL(u),host));
});
test('cookie parser rejects duplicates and malformed tokens', () => {
  assert.equal(readCookie(new Request('https://x',{headers:{cookie:`s=${nonce}`}}),'s'),nonce);
  assert.equal(readCookie(new Request('https://x',{headers:{cookie:`s=${nonce}; s=${session}`}}),'s'),undefined);
});
test('anonymous and expired sessions cannot reach upstream', async () => {
  const {gateway,records,calls,upstream,req} = fixture();
  const landing = await gateway.handle(req('/'),upstream);
  assert.match(landing.headers.get('content-security-policy')!, /form-action 'self' https:\/\/bsky\.social;/);
  assert.equal((await gateway.handle(req('/xrpc/vlpds.admin.getClusterStatus'),upstream)).status,401);
  records.set(`session:${session}`,{value:did,expires:0});
  assert.equal((await gateway.handle(req('/xrpc/vlpds.admin.getClusterStatus',{headers:{cookie:`__Host-crate-operator=${session}`}}),upstream)).status,401);
  assert.equal(calls.length,0);
});
test('authenticated API requires same-origin and injects server token only upstream',async () => {
  const {gateway,records,calls,upstream,req} = fixture();
  records.set(`session:${session}`,{value:did,expires:Date.now()+10000});
  const headers = {cookie:`__Host-crate-operator=${session}`,'sec-fetch-site':'cross-site'};
  assert.equal((await gateway.handle(req('/xrpc/vlpds.admin.getClusterStatus',{headers}),upstream)).status,403);
  headers['sec-fetch-site']='same-origin';
  const response = await gateway.handle(req('/xrpc/vlpds.admin.getClusterStatus',{headers}),upstream);
  assert.equal(response.status,200);
  assert.equal(calls[0].headers.get('cookie'),null);
  assert.equal(calls[0].headers.get('authorization'),`Basic ${btoa('admin:never-send-to-browser')}`);
  assert(!(await response.text()).includes('never-send'));
  assert.equal((await gateway.handle(req('/xrpc/vlpds.admin.createInviteCode',{method:'POST',headers}),upstream)).status,403);
});
test('callback binds browser nonce, rejects other DIDs, and consumes login once',async () => {
  for (const [callbackDid,callbackState,expected] of [[did,nonce,303],['did:plc:other',nonce,403],[did,session,403]] as const) {
    const {gateway,records,upstream,req} = fixture();
    records.set(`login:${nonce}`,{value:true,expires:Date.now()+10000});
    (gateway as any).client={callback:async () => ({session:{did:callbackDid},state:callbackState})};
    const request = () => req('/operator/callback?code=test&state=state',{headers:{cookie:`__Host-crate-login=${nonce}`}});
    const response = await gateway.handle(request(),upstream);
    assert.equal(response.status,expected);
    assert.equal((await gateway.handle(request(),upstream)).status,400);
    assert.equal([...records.keys()].filter(k=>k.startsWith('session:')).length,expected===303?1:0);
    if(expected===303) assert.match(response.headers.get('set-cookie')!, /Secure; HttpOnly; SameSite=Lax/);
  }
});
test('logout requires origin and revokes server-side session',async () => {
  const {gateway,records,upstream,req}=fixture();
  records.set(`session:${session}`,{value:did,expires:Date.now()+10000});
  const headers={cookie:`__Host-crate-operator=${session}`,origin:`https://${host}`};
  assert.equal((await gateway.handle(req('/operator/logout',{method:'POST',headers}),upstream)).status,303);
  assert(!records.has(`session:${session}`));
});
test('responses prohibit caching and cross-origin API access', () => {
  const response=secure(new Response('x',{headers:{'access-control-allow-origin':'*'}}));
  assert.equal(response.headers.get('cache-control'),'no-store');
  assert.equal(response.headers.get('referrer-policy'),'strict-origin');
  assert.equal(response.headers.get('access-control-allow-origin'),null);
});
test('OAuth JSON limits reject oversized collections and deep nesting', () => {
  validateJsonSize({issuer:'https://example.com',jwks:{keys:[]}});
  assert.throws(()=>validateJsonSize(Array(129).fill(null)));
  let deep:any=null; for(let i=0;i<22;i++) deep={deep};
  assert.throws(()=>validateJsonSize(deep));
});
test('OAuth fetch rejects redirects and oversized JSON before SDK parsing',async () => {
  const {oauthFetch}=await import('../src/oauth-fetch.ts');
  const original=globalThis.fetch;
  try {
    globalThis.fetch=async () => new Response(null,{status:302,headers:{location:'https://evil.example'}});
    await assert.rejects(oauthFetch('https://example.com'),/redirects/);
    globalThis.fetch=async () => new Response(JSON.stringify(Array(129).fill(null)));
    await assert.rejects(oauthFetch('https://example.com'),/collection/);
    globalThis.fetch=async () => new Response('x'.repeat(65537));
    await assert.rejects(oauthFetch('https://example.com'),/too large/);
    await assert.rejects(oauthFetch('http://example.com'),/HTTPS/);
  } finally {globalThis.fetch=original;}
});

test('standard invite API stays behind session and same-origin checks', async () => {
  const {gateway,records,calls,upstream,req}=fixture();
  const path='/xrpc/com.atproto.server.createInviteCodes';
  assert(operatorPath(new URL(`https://${host}${path}`),host));
  assert(!operatorPath(new URL(`https://${host}/xrpc/com.atproto.server.createSession`),host));
  assert.equal((await gateway.handle(req(path,{method:'POST'}),upstream)).status,401);
  records.set(`session:${session}`,{value:did,expires:Date.now()+10000});
  const headers={cookie:`__Host-crate-operator=${session}`,origin:`https://${host}`,'sec-fetch-site':'cross-site','content-type':'application/json'};
  assert.equal((await gateway.handle(req(path,{method:'POST',headers}),upstream)).status,403);
  headers['sec-fetch-site']='same-origin';
  const body=JSON.stringify({codeCount:1,useCount:1});
  assert.equal((await gateway.handle(req(path,{method:'POST',headers,body}),upstream)).status,200);
  assert.equal(calls.length,1);
  assert.equal(await calls[0].text(),body);
  assert(calls[0].headers.get('authorization')?.startsWith('Basic '));
});
