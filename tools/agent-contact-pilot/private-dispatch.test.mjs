import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createPilot, openLedger, agentPath, fixedData, fixedRequest } from './pilot.mjs';
import { signedPrivateDispatch } from './private-dispatch.mjs';

test('private hop requires its separate pinned identity and caches same event before synthetic proof/profile dispatch', async t => {
  const keys = generateKeyPairSync('ed25519'); const ledger = openLedger(':memory:'); let calls = 0;
  const server = createPilot({ enabled: true, ledger,
    senders: [{ sender: 'private-ingress', keyId: 'bridge-key', publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }) }],
    dispatch: async () => { calls++; return { ...fixedData, status: 'verified' }; } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(r => server.close(r)); ledger.close(); });
  const endpoint = `http://127.0.0.1:${server.address().port}${agentPath}`;
  const dispatch = signedPrivateDispatch(endpoint, { ...keys, sender: 'private-ingress', keyId: 'bridge-key' });
  const first = await dispatch('private-event');
  assert.equal(first.status, 'verified');
  assert.deepEqual(await dispatch('private-event'), first);
  assert.equal(calls, 1, 'directly counted injected synthetic proof/profile dispatch');
  const unsigned = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(fixedRequest('unsigned')) });
  assert.equal(unsigned.status, 401);
  const wrong = signedPrivateDispatch(endpoint, { privateKey: generateKeyPairSync('ed25519').privateKey, sender: 'private-ingress', keyId: 'bridge-key' });
  await assert.rejects(wrong('wrong-key'));
  assert.equal(calls, 1);
  for (const endpoint of ['https://unconfigured.invalid/a2a/v1', 'http://localhost:12345'+agentPath, 'http://127.0.0.1:12345/a2a/v1']) {
    assert.throws(() => signedPrivateDispatch(endpoint, { ...keys }));
  }
});

test('private hop rejects mismatched RPC correlation and oversized response without a second attempt', async t => {
  let calls = 0; let oversized = false; let valid = false;
  const server = createServer((req, res) => { calls++; req.resume(); res.writeHead(200, { 'content-type': 'Application/JSON ; charset=utf-8' }); res.end(valid ? JSON.stringify({jsonrpc:'2.0',id:'valid',result:{message:{role:'ROLE_AGENT',contextId:'context',parts:[{data:{...fixedData,status:'verified'}}]}}}) : oversized ? ' '.repeat(4097) : JSON.stringify({ jsonrpc:'2.0', id:'other', result:{} })); });
  server.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
  const dispatch = signedPrivateDispatch(`http://127.0.0.1:${server.address().port}${agentPath}`, { ...generateKeyPairSync('ed25519'), sender:'bridge',keyId:'key' });
  await assert.rejects(dispatch('event'),/correlation/);assert.equal(calls,1);
  oversized = true;await assert.rejects(dispatch('large'));assert.equal(calls,2);
  valid = true;assert.equal((await dispatch('valid')).status,'verified');assert.equal(calls,3);
});

test('structurally invalid JSON responses use a generic protocol error', async t => {
  let reply = null;
  const server = createServer((req,res)=>{req.resume();res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(reply));});
  server.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
  const dispatch=signedPrivateDispatch(`http://127.0.0.1:${server.address().port}${agentPath}`,{...generateKeyPairSync('ed25519'),sender:'bridge',keyId:'key'});
  for (const value of [null,{}, {jsonrpc:'2.0',id:'bad',result:{message:{role:'ROLE_AGENT',contextId:'context'}}}]) {
    reply=value; await assert.rejects(dispatch('bad'), /^Error: Invalid private dispatch correlation$/);
  }
});
