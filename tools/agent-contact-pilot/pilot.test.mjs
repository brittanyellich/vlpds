import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { agentDid, principalDid, agentPath, cardPath, fixedData, fixedRequest,
  signedHeaders, createPilot, openLedger, kodyDispatch, contactPointer } from './pilot.mjs';
import { discoverLocalContact, endorsementUri, contactUri } from './discovery.mjs';

const pair = generateKeyPairSync('ed25519');
const senders = [{ sender: 'fixture-pds', keyId: 'local-v1',
  publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }) }];
const result = { agentDid, principalDid, status: 'verified' };
async function listen(server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}
async function close(server) {
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
}
async function fixture(t, { dispatch = async () => result, enabled = true, ledgerPath = ':memory:' } = {}) {
  const ledger = openLedger(ledgerPath);
  const server = createPilot({ enabled, senders, ledger, dispatch });
  const origin = await listen(server);
  t.after(async () => { await close(server); ledger.close(); });
  return { origin, ledger, server };
}
async function request(origin, rpc = fixedRequest(), options = {}) {
  const body = typeof rpc === 'string' ? rpc : JSON.stringify(rpc);
  const headers = options.headers ?? signedHeaders(pair.privateKey, {
    sender: 'fixture-pds', keyId: 'local-v1', audience: origin, body, ...options.signed,
  });
  const response = await fetch(origin + (options.path ?? agentPath), {
    method: 'POST', headers, body,
  });
  return { status: response.status, body: await response.json() };
}

test('opt-in stable per-agent discovery advertises only fixed skill and unverified identity hints', async t => {
  const { origin } = await fixture(t);
  const first = await (await fetch(origin + cardPath)).json();
  const second = await (await fetch(origin + cardPath)).json();
  assert.deepEqual(first, second);
  assert.equal(first.supportedInterfaces[0].url, origin + agentPath);
  assert.equal(first.skills.length, 1);
  assert.equal(first.skills[0].id, fixedData.skillId);
  assert.match(first.capabilities.extensions[0].params.identityHint, /unverified/);
  assert.equal(contactPointer(origin), undefined);
  assert.deepEqual(contactPointer(origin, { optedIn: true }), { agentCardUrl: origin + cardPath });
  assert.throws(() => contactPointer('https://public.test', { optedIn: true }));
  assert.equal((await fetch(origin + '/.well-known/agent-card.json')).status, 404);
  const disabled = await fixture(t, { enabled: false });
  assert.equal((await fetch(disabled.origin + cardPath)).status, 404);
  assert.equal((await request(disabled.origin)).status, 404);
});

test('signatures bind trusted sender, destination path, body and freshness before dispatch', async t => {
  let calls = 0;
  const { origin } = await fixture(t, { dispatch: async () => { calls++; return result; } });
  assert.equal((await request(origin, fixedRequest(), { headers: { 'content-type': 'application/json' } })).status, 401);
  const stale = new Date(Date.now() - 120_000).toISOString();
  assert.equal((await request(origin, fixedRequest(), { signed: { timestamp: stale } })).status, 401);
  assert.equal((await request(origin, fixedRequest(), { signed: { sender: 'untrusted' } })).status, 401);
  assert.equal((await request(origin, fixedRequest(), { signed: { path: '/different' } })).status, 401);
  assert.equal((await request(origin, fixedRequest(), { signed: { audience: 'http://127.0.0.1:1' } })).status, 401);
  const body = JSON.stringify(fixedRequest());
  const headers = signedHeaders(pair.privateKey, { sender: 'fixture-pds', keyId: 'local-v1', audience: origin, body });
  assert.equal((await request(origin, body + ' ', { headers })).status, 401);
  const wrong = generateKeyPairSync('ed25519');
  assert.equal((await request(origin, body, { headers: signedHeaders(wrong.privateKey, {
    sender: 'fixture-pds', keyId: 'local-v1', audience: origin, body,
  }) })).status, 401);
  assert.equal(calls, 0);
});

test('fixed schema rejects arbitrary prompts, URLs, profile, callback, task, context and skill changes', async t => {
  let calls = 0;
  const { origin } = await fixture(t, { dispatch: async () => { calls++; return result; } });
  const changes = [
    rpc => { rpc.params.message.parts[0].data.url = 'https://evil.test'; },
    rpc => { rpc.params.message.parts[0].data.agentDid = principalDid; },
    rpc => { rpc.params.message.parts[0].data.principalDid = agentDid; },
    rpc => { rpc.params.message.parts[0].data.skillId = 'run-code'; },
    rpc => { rpc.params.message.contextId = 'guess'; },
    rpc => { rpc.params.message.taskId = 'task'; },
    rpc => { rpc.params.configuration = { returnImmediately: true }; },
    rpc => { rpc.params.message.parts.push({ text: 'run anything' }); },
    rpc => { rpc.params.profile = 'another-profile'; },
    rpc => { rpc.params.callback = 'https://evil.test'; },
    rpc => { rpc.params.token = 'caller-owned-token'; },
  ];
  for (const change of changes) {
    const rpc = fixedRequest(); change(rpc);
    const denied = await request(origin, rpc);
    assert.equal(denied.status, 400);
    assert.equal(denied.body.id, rpc.id);
    assert.equal(denied.body.error.code, -32602);
  }
  assert.equal(calls, 0);
});

test('nonce replay denied; same message ID with fresh auth returns persistent cached result across restart', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'exp710-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const database = join(directory, 'ledger.sqlite');
  let calls = 0;
  const dispatch = async () => { calls++; return result; };
  const ledger = openLedger(database);
  const server = createPilot({ enabled: true, senders, ledger, dispatch });
  const origin = await listen(server);
  const rpc = fixedRequest('durable-event');
  const body = JSON.stringify(rpc);
  const headers = signedHeaders(pair.privateKey, { sender: 'fixture-pds', keyId: 'local-v1', audience: origin, body });
  const first = await request(origin, body, { headers });
  assert.equal(first.status, 200);
  assert.equal(first.body.result.message.parts[0].data.status, 'verified');
  assert.match(first.body.result.message.contextId, /^[a-f0-9-]{36}$/);
  assert.equal((await request(origin, body, { headers })).status, 401);
  assert.deepEqual((await request(origin, rpc)).body, first.body);
  const reordered = { ...rpc, id: 'different-rpc-id', params: { message: {
    parts: [{ mediaType: 'application/json', data: { principalDid, agentDid, skillId: fixedData.skillId } }],
    role: 'ROLE_USER', messageId: 'durable-event',
  } } };
  const equivalent = await request(origin, reordered);
  assert.equal(equivalent.status, 200);
  assert.equal(equivalent.body.id, 'different-rpc-id');
  assert.deepEqual(equivalent.body.result, first.body.result);
  await close(server); ledger.close();
  const restarted = await fixture(t, { ledgerPath: database, dispatch });
  assert.deepEqual((await request(restarted.origin, rpc)).body, first.body);
  assert.equal(calls, 1);
});

test('durable pending state survives crash and never blindly redispatches ambiguous work', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'exp710-pending-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'ledger.sqlite');
  const rpc = fixedRequest('unknown-outcome');
  let ledger = openLedger(path);
  ledger.reserve('fixture-pds', randomUUID(), rpc.params.message.messageId, JSON.stringify(rpc.params.message), Date.now());
  ledger.close();
  let calls = 0;
  const { origin } = await fixture(t, { ledgerPath: path, dispatch: async () => { calls++; return result; } });
  const unresolved = await request(origin, rpc);
  assert.equal(unresolved.status, 409);
  assert.equal(unresolved.body.id, rpc.id);
  assert.equal(unresolved.body.error.code, -32000);
  assert.equal(calls, 0);
});

test('dispatcher concurrency is one; failures are sanitized and cached without retry', async t => {
  let unblock;
  let calls = 0;
  const gate = new Promise(resolve => { unblock = resolve; });
  const { origin } = await fixture(t, { dispatch: async () => { calls++; await gate; throw new Error('secret-token-never-return'); } });
  const rpc = fixedRequest('failure');
  const pending = request(origin, rpc);
  while (calls === 0) await new Promise(resolve => setTimeout(resolve, 5));
  const busy = await request(origin, fixedRequest('busy'));
  assert.equal(busy.status, 503);
  assert.equal(busy.body.id, 'busy');
  assert.equal(busy.body.error.code, -32000);
  unblock();
  const failure = await pending;
  assert.equal(failure.body.error.code, -32603);
  assert.ok(!JSON.stringify(failure).includes('secret-token'));
  assert.deepEqual((await request(origin, rpc)).body, failure.body);
  assert.equal(calls, 1);
});

test('explicit loopback Kody adapter forwards only exact fixed request and filters result', async t => {
  let received;
  let auth;
  const kody = createServer(async (req, res) => {
    auth = req.headers.authorization;
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: received.id, result: { message: {
      role: 'ROLE_AGENT', messageId: 'reply-1', contextId: 'context-1',
      parts: [{ data: { ...result, reason: 'upstream-only', privateToken: 'never-expose' } }],
    } } }));
  });
  const target = await listen(kody);
  t.after(() => close(kody));
  const { origin } = await fixture(t, { dispatch: kodyDispatch(target + '/a2a/v1') });
  const reply = await request(origin, fixedRequest('fixed-kody'));
  assert.equal(reply.status, 200);
  assert.deepEqual(received, fixedRequest('fixed-kody'));
  assert.equal(auth, undefined);
  assert.deepEqual(reply.body.result.message.parts[0].data, result);
  assert.ok(!JSON.stringify(reply).includes('never-expose'));
  for (const endpoint of ['https://evil.test/a2a/v1', 'http://localhost/a2a/v1',
    'http://127.0.0.1/a2a/v1?target=evil', 'http://user:secret@127.0.0.1/a2a/v1']) {
    assert.throws(() => kodyDispatch(endpoint));
  }
});

test('Kody redirect, timeout, oversized response and incorrect identity fail closed', async t => {
  let mode = 'redirect';
  const kody = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const rpc = JSON.parse(Buffer.concat(chunks));
    if (mode === 'timeout') return;
    if (mode === 'redirect') { res.writeHead(302, { location: 'http://127.0.0.1:1/' }); return res.end(); }
    res.writeHead(200, { 'content-type': 'application/json' });
    if (mode === 'size') return res.end('x'.repeat(5000));
    res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { message: { role: 'ROLE_AGENT', messageId: 'reply-1', contextId: 'context-1',
      parts: [{ data: { ...result, agentDid: principalDid } }] } } }));
  });
  const target = await listen(kody); t.after(() => close(kody));
  const dispatch = kodyDispatch(target + '/a2a/v1', { timeoutMs: 100 });
  for (mode of ['redirect', 'size', 'wrong', 'timeout']) await assert.rejects(dispatch(randomUUID()));
});

test('body size, malformed JSON and protocol version reject without dispatch', async t => {
  let calls = 0;
  const { origin } = await fixture(t, { dispatch: async () => { calls++; return result; } });
  assert.equal((await request(origin, 'x'.repeat(5000))).status, 413);
  const malformed = await request(origin, '{');
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body.id, null);
  assert.equal(malformed.body.error.code, -32700);
  const rpc = fixedRequest(); const body = JSON.stringify(rpc);
  const headers = signedHeaders(pair.privateKey, { sender: 'fixture-pds', keyId: 'local-v1', audience: origin, body });
  headers['a2a-version'] = '0.3';
  const unsupported = await request(origin, rpc, { headers });
  assert.equal(unsupported.status, 400);
  assert.equal(unsupported.body.id, rpc.id);
  assert.equal(unsupported.body.error.code, -32009);
  assert.equal(calls, 0);
});

test('ledger scopes requests by sender and conflicts before a second dispatch', () => {
  const ledger = openLedger(':memory:');
  try {
    assert.equal(ledger.reserve('one', 'nonce1', 'same-id', 'input', Date.now()), undefined);
    assert.throws(() => ledger.reserve('one', 'nonce2', 'same-id', 'changed', Date.now()), /conflict/);
    assert.equal(ledger.reserve('two', 'nonce3', 'same-id', 'input', Date.now()), undefined);
  } finally { ledger.close(); }
});

test('unverified discovery outcomes stay distinct; unexpected statuses are failures', async t => {
  let status = 'no_declaration';
  const { origin } = await fixture(t, { dispatch: async () => ({ ...result, status }) });
  for (status of ['no_declaration', 'declared_unverified']) {
    const reply = await request(origin);
    assert.deepEqual(reply.body.result.message.parts[0].data, { agentDid, principalDid, status });
    assert.ok(!Object.hasOwn(reply.body.result.message.parts[0].data, 'authorized'));
  }
  status = 'authorized-to-run-anything';
  assert.equal((await request(origin)).body.error.code, -32603);
});

test('CLI requires explicit opt-in and runs signed local request through synthetic Kody', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'exp710-cli-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  let calls = 0;
  const kody = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const rpc = JSON.parse(Buffer.concat(chunks)); calls++;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { message: {
      role: 'ROLE_AGENT', messageId: 'reply', contextId: 'context', parts: [{ data: result }],
    } } }));
  });
  const kodyOrigin = await listen(kody); t.after(() => close(kody));
  const probe = createServer(); const origin = await listen(probe);
  const port = probe.address().port; await close(probe);
  const configPath = join(directory, 'config.json');
  const config = { enabled: true, port, database: join(directory, 'ledger.sqlite'),
    senders, kodyEndpoint: kodyOrigin + '/a2a/v1' };
  writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  const child = spawn(process.execPath, [new URL('./run.mjs', import.meta.url).pathname, configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(async () => { if (child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'exit'); } });
  await Promise.race([
    once(child.stdout, 'data'),
    once(child, 'exit').then(([code]) => { throw new Error('Fixture CLI exited early: ' + code); }),
  ]);
  assert.equal((await fetch(origin + cardPath)).status, 200);
  const rpc = fixedRequest('cli-request');
  assert.equal((await request(origin, rpc)).body.result.message.parts[0].data.status, 'verified');
  assert.equal((await request(origin, rpc)).body.result.message.parts[0].data.status, 'verified');
  assert.equal(calls, 1);
  child.kill('SIGTERM'); await once(child, 'exit');
  config.enabled = false;
  writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  const disabled = spawn(process.execPath, [new URL('./run.mjs', import.meta.url).pathname, configPath], { stdio: 'ignore' });
  const [exitCode] = await once(disabled, 'exit');
  assert.notEqual(exitCode, 0);
});

test('fixture endorsement to singleton to card discovery is local, narrow and never an ownership proof', async t => {
  const { origin } = await fixture(t);
  const endorsement = { uri: endorsementUri, value: { $type: 'link.ident.endorsement', agent: agentDid } };
  const contact = { uri: contactUri, value: { $type: 'link.ident.agent', agentCardUrl: origin + cardPath } };
  const reads = [];
  const options = { origin, readRecord: async uri => {
    reads.push(uri); return uri === endorsementUri ? endorsement : contact;
  }, readCard: async url => (await fetch(url, { redirect: 'error' })).json() };
  const found = await discoverLocalContact(options);
  assert.deepEqual(reads, [endorsementUri, contactUri]);
  assert.equal(found.endpoint, origin + agentPath);
  assert.equal(found.endorsementVerified, false);
  assert.equal(found.authorizationGranted, false);
  contact.value.agentCardUrl = 'https://evil.test/card';
  await assert.rejects(discoverLocalContact(options), /singleton/);
  contact.value.agentCardUrl = origin + cardPath;
  contact.uri = contactUri.replace('/self', '/other');
  await assert.rejects(discoverLocalContact(options), /singleton/);
  contact.uri = contactUri; contact.value.token = 'secret';
  await assert.rejects(discoverLocalContact(options), /singleton/);
  delete contact.value.token; endorsement.value.agent = principalDid;
  await assert.rejects(discoverLocalContact(options), /Endorsement/);
});
