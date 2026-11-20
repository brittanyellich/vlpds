import { test } from 'node:test';
import assert from 'node:assert/strict';
import { permitted, forwarded, containerRequest } from '../src/routing.ts';
const host = 'pds.crate.social';
const allowed = (path: string) => permitted(new URL(`https://${host}${path}`), host, 'crate.social');
test('public protocols and account pages remain reachable', () => {
  for (const p of ['/', '/migrate', '/oauth/authorize', '/.well-known/did.json',
    '/xrpc/com.atproto.sync.subscribeRepos', '/xrpc/com.atproto.space.importRepo']) assert.ok(allowed(p), p);
});
test('operator and internal surfaces are denied, including encoded bypasses', () => {
  for (const p of ['/admin', '/admin/', '/metrics', '/internal/a', '/debug/pprof/heap',
    '/xrpc/vlpds.admin.getClusterStatus', '/xrpc/vlpds.internal.any', '/%61dmin', '/admin%2f',
    '/xrpc/vlpds%2eadmin.getClusterStatus']) assert.equal(allowed(p), false, p);
});
test('wildcard hosts only resolve handles, and unrelated hosts fail closed', () => {
  assert.ok(permitted(new URL('https://ada.crate.social/.well-known/atproto-did'), host, 'crate.social'));
  for (const u of ['https://ada.crate.social/admin', 'https://ada.crate.social/xrpc/com.atproto.server.createSession',
    'https://a.b.crate.social/.well-known/atproto-did', 'https://evilpds.crate.social/', 'http://pds.crate.social/',
    'https://pds.crate.social:8443/']) assert.equal(permitted(new URL(u), host, 'crate.social'), false, u);
});
test('proxy headers are replaced while auth and WebSocket headers survive', () => {
  const r = forwarded(new Request('https://pds.crate.social/xrpc/com.atproto.sync.subscribeRepos', { headers: {
    'x-forwarded-for': 'spoof', 'forwarded': 'for=spoof', 'tailscale-user-login': 'admin',
    'cf-access-jwt-assertion': 'spoof', 'cf-connecting-ip': '192.0.2.4',
    'authorization': 'Bearer session', 'upgrade': 'websocket',
  }}));
  assert.equal(r.headers.get('x-forwarded-for'), '192.0.2.4');
  assert.equal(r.headers.get('forwarded'), null);
  assert.equal(r.headers.get('tailscale-user-login'), null);
  assert.equal(r.headers.get('cf-access-jwt-assertion'), null);
  assert.equal(r.headers.get('authorization'), 'Bearer session');
  assert.equal(r.headers.get('upgrade'), 'websocket');
});

test('container transport uses HTTP while retaining host, proxy scheme and streamed body', async () => {
  const request = forwarded(new Request('https://pds.crate.social/xrpc/com.atproto.repo.uploadBlob?x=1', {
    method: 'POST', body: 'blob bytes', headers: { 'content-type': 'application/octet-stream' },
  }));
  const internal = containerRequest(request);
  assert.equal(internal.url, 'http://pds.crate.social/xrpc/com.atproto.repo.uploadBlob?x=1');
  assert.equal(internal.headers.get('host'), 'pds.crate.social');
  assert.equal(internal.headers.get('x-forwarded-proto'), 'https');
  assert.equal(internal.method, 'POST');
  assert.equal(await internal.text(), 'blob bytes');
});

 test('native agent encoding exception is exact, public-host-only and default off', () => {
 const card='/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/.well-known/agent-card.json';
 const post='/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/a2a/v1';
 for(const path of [card,post]){
  assert.equal(permitted(new URL(`https://${host}${path}`),host,'crate.social'),false);
  assert.equal(permitted(new URL(`https://${host}${path}`),host,'crate.social',true),true);
 }
 for(const path of [post+'?x=1',post+'/',post.replaceAll('%3A',':'),'/private/agent-profile/assert',post.replaceAll('%3A','%3a'),post.replaceAll('%3A','%253A'),post.replace('6tlvgafuonoighfrtpejff5m','aaaaaaaaaaaaaaaaaaaaaaaa'),'/agents/%2e%2e/admin'])
 assert.equal(permitted(new URL(`https://${host}${path}`),host,'crate.social',true),false,path);
 assert.equal(permitted(new URL('https://ada.crate.social'+post),host,'crate.social',true),false);
 });
