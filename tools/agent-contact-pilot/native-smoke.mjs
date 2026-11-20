import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createPilot, openLedger, kodyDispatch, fixedRequest, signedHeaders,
  cardPath, agentPath, agentDid, principalDid } from './pilot.mjs';
import { discoverLocalContact, endorsementUri, contactUri } from './discovery.mjs';

process.umask(0o077);
const binary = resolve(process.argv[2] ?? '../../target/debug/vlpds');
const evidencePath = process.argv[3];
const directory = mkdtempSync(join(tmpdir(), 'exp710-native-'));
const servers = [];
const children = [];
const ledger = openLedger(join(directory, 'ledger.sqlite'));
const evidence = { binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
  scope: 'Actual native PDS binary and authenticated sidecar, synthetic Kody endpoint, JSON-only local record fixtures; no real account writes or CAR parsing' };
async function listen(server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); servers.push(server);
  return `http://127.0.0.1:${server.address().port}`;
}
async function freeOrigin() {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  await new Promise(resolve => server.close(resolve)); return origin;
}
async function startPds(origin, backend, extra = []) {
  const args = ['--dev-mode', '--memory', '--listen', origin.slice(7), '--public-url', origin,
    '--workers', '1', '--io-threads', '2', '--shards', '1', '--firehose-threads', '0',
    '--cache-per-worker', '32', '--memory-budget-mb', '1536', '--no-rate-limits',
    '--firehose-ring-mb', '8', '--firehose-merge-queue-mb', '8', '--live-ring-mb', '8',
    '--lazy-mst-node-cache-mb', '8', '--backfill-readahead-mb', '1', '--backfill-cache-mb', '8',
    '--firehose-max-backfills', '1', '--max-exports', '1',
    '--plc-mode', 'unregistered', '--plc-url', 'http://127.0.0.1:9'];
  if (backend) args.push('--agent-contact-pilot', backend);
  const child = spawn(binary, [...args, ...extra], {
    cwd: directory, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', RUST_LOG: 'warn' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let diagnostic = ''; child.stderr.on('data', bytes => { diagnostic = (diagnostic + bytes).slice(-4096); });
  for (let n = 0; n < 200; n++) {
    if (child.exitCode !== null) throw new Error('Native fixture startup failed: ' + diagnostic);
    try {
      const response = await fetch(origin + '/xrpc/_health', { signal: AbortSignal.timeout(300) });
      if (response.ok) return child;
    } catch {}
    await delay(100);
  }
  throw new Error('Native fixture startup timed out');
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  const exited = once(child, 'exit');
  const timeout = setTimeout(() => child.kill('SIGKILL'), 5000);
  await exited; clearTimeout(timeout);
}
try {
  const publicOrigin = await freeOrigin();
  let dispatchCount = 0;
  const kody = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const rpc = JSON.parse(Buffer.concat(chunks)); dispatchCount++;
    assert.deepEqual(rpc, fixedRequest(rpc.params.message.messageId));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { message: {
      role: 'ROLE_AGENT', messageId: 'synthetic-reply', contextId: 'synthetic-context',
      parts: [{ data: { agentDid, principalDid, status: 'verified' } }],
    } } }));
  });
  const kodyOrigin = await listen(kody);
  const pair = generateKeyPairSync('ed25519');
  const sidecar = createPilot({ enabled: true, ledger, publicOrigin,
    senders: [{ sender: 'native-fixture', keyId: 'ephemeral', publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }) }],
    dispatch: kodyDispatch(kodyOrigin + '/a2a/v1'),
  });
  const backend = await listen(sidecar);
  const pds = await startPds(publicOrigin, backend);
  const readCard = async url => {
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(2000) });
    assert.equal(response.status, 200);
    return response.json();
  };
  const card = await readCard(publicOrigin + cardPath);
  assert.equal(card.supportedInterfaces[0].url, publicOrigin + agentPath);
  assert.ok(!JSON.stringify(card).includes(backend));
  const endorsement = JSON.parse(readFileSync(new URL('./fixtures/principal-endorsement.json', import.meta.url)));
  const contact = JSON.parse(readFileSync(new URL('./fixtures/link.ident.agent.self.json', import.meta.url)));
  contact.value.agentCardUrl = publicOrigin + cardPath;
  const records = new Map([[endorsementUri, endorsement], [contactUri, contact]]);
  const reads = [];
  evidence.discovery = await discoverLocalContact({ origin: publicOrigin,
    readRecord: async uri => { reads.push(uri); return records.get(uri); }, readCard });
  assert.deepEqual(reads, [endorsementUri, contactUri]);
  const rpc = fixedRequest('native-event');
  const send = async (value, headers) => {
    const body = JSON.stringify(value);
    const response = await fetch(publicOrigin + agentPath, { method: 'POST', body,
      headers: headers ?? signedHeaders(pair.privateKey, { sender: 'native-fixture', keyId: 'ephemeral', audience: publicOrigin, body }) });
    return { status: response.status, body: await response.json() };
  };
  const body = JSON.stringify(rpc);
  const headers = signedHeaders(pair.privateKey, { sender: 'native-fixture', keyId: 'ephemeral', audience: publicOrigin, body });
  assert.equal((await send(rpc, { 'content-type': 'application/json' })).status, 401);
  evidence.first = await send(rpc, headers); assert.equal(evidence.first.status, 200);
  assert.equal(evidence.first.body.result.message.parts[0].data.status, 'verified');
  evidence.exactReplay = (await send(rpc, headers)).status; assert.equal(evidence.exactReplay, 401);
  evidence.cachedRetry = await send({ ...rpc, id: 'retry-rpc' });
  assert.deepEqual(evidence.cachedRetry.body.result, evidence.first.body.result);
  assert.equal(evidence.cachedRetry.body.id, 'retry-rpc'); assert.equal(dispatchCount, 1);
  const tampered = fixedRequest('tampered'); tampered.params.message.parts[0].data.principalDid = agentDid;
  assert.equal((await send(tampered)).status, 400);
  const wrongAudience = signedHeaders(pair.privateKey, { sender: 'native-fixture', keyId: 'ephemeral', audience: backend, body });
  assert.equal((await send(rpc, wrongAudience)).status, 401);
  const large = 'x'.repeat(5000);
  assert.equal((await fetch(publicOrigin + agentPath, { method: 'POST', body: large,
    headers: signedHeaders(pair.privateKey, { sender: 'native-fixture', keyId: 'ephemeral', audience: publicOrigin, body: large }) })).status, 413);
  evidence.dispatchCount = dispatchCount;
  await stop(pds);
  const disabledOrigin = await freeOrigin();
  const disabled = await startPds(disabledOrigin);
  evidence.disabledCardStatus = (await fetch(disabledOrigin + cardPath)).status;
  assert.equal(evidence.disabledCardStatus, 404);
  await stop(disabled);
  evidence.result = 'PASS';
} finally {
  for (const child of children) await stop(child);
  for (const server of servers.reverse()) {
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  }
  ledger.close(); rmSync(directory, { recursive: true, force: true });
  evidence.cleanup = { allOwnedNativeProcessesExited: children.every(c => c.exitCode !== null || c.signalCode !== null),
    localListenersClosed: true, temporaryLedgerAndKeysRemoved: true };
  if (evidencePath) writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify({ result: evidence.result ?? 'FAILED', evidencePath, cleanup: evidence.cleanup }));
}
