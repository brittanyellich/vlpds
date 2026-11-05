import { test } from 'node:test';
import assert from 'node:assert/strict';
import { permitted, forwarded } from '../src/routing.ts';
const host = 'pds.ellich.at';
const allowed = (path: string) => permitted(new URL(`https://${host}${path}`), host);
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
  assert.ok(permitted(new URL('https://ada.pds.ellich.at/.well-known/atproto-did'), host));
  for (const u of ['https://ada.pds.ellich.at/admin', 'https://ada.pds.ellich.at/xrpc/com.atproto.server.createSession',
    'https://a.b.pds.ellich.at/.well-known/atproto-did', 'https://evilpds.ellich.at/', 'http://pds.ellich.at/',
    'https://pds.ellich.at:8443/']) assert.equal(permitted(new URL(u), host), false, u);
});
test('proxy headers are replaced while auth and WebSocket headers survive', () => {
  const r = forwarded(new Request('https://pds.ellich.at/xrpc/com.atproto.sync.subscribeRepos', { headers: {
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
