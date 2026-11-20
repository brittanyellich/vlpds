import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { createFixedCardResolver, openCardKeyJournal, fixedDid } from './card-resolver.mjs';
import { signLocalCard, publicMultibase, identityExtension } from './signed-card.mjs';

function identity() {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const doc = { id: fixedDid, verificationMethod: [{ id: fixedDid + '#card-signing', controller: fixedDid,
    type: 'Multikey', publicKeyMultibase: publicMultibase(keys.privateKey) }] };
  const origin = 'http://127.0.0.1:32123';
  const card = signLocalCard({ name: 'Synthetic fixed-DID resolver test', version: '0.1.0',
    supportedInterfaces: [{ url: origin + '/a2a/v1', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    capabilities: { extensions: [{ uri: identityExtension, params: { did: fixedDid } }] },
    skills: [{ id: 'resolve-identity-fixture', name: 'Synthetic read only' }],
  }, keys.privateKey);
  return { doc, options: { publisherDid: fixedDid, record: { uri: `at://${fixedDid}/link.ident.agent/self`,
    value: { $type: 'link.ident.agent', agentCardUrl: origin + '/card' } }, card,
    expectedCardUrl: origin + '/card', expectedEndpoint: origin + '/a2a/v1' } };
}

async function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'exp710-resolver-'));
  const certPath = join(directory, 'ca.pem'); const keyPath = join(directory, 'tls-key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
    '-keyout', keyPath, '-out', certPath], { stdio: 'ignore' });
  const state = { doc: identity().doc, calls: 0, paths: [], mode: 'json', wait: 0 };
  const server = https.createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, async (req, res) => {
    state.calls++; state.paths.push(req.url);
    const mode = state.mode; const document = structuredClone(state.doc);
    if (state.wait) await delay(state.wait);
    if (mode === 'redirect') { res.writeHead(302, { location: 'https://unconfigured.invalid/key' }); return res.end(); }
    if (mode === 'missing') { res.writeHead(404); return res.end(); }
    if (mode === 'error') { res.writeHead(503); return res.end(); }
    res.writeHead(200, { 'content-type': 'application/json' });
    if (mode === 'hang') { res.write('{'); return; }
    if (mode === 'large') return res.end(' '.repeat(33000));
    if (mode === 'invalid') return res.end('{');
    res.end(JSON.stringify(document));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const origin = `https://127.0.0.1:${server.address().port}`;
  const clients = []; const journals = [];
  t.after(async () => {
    for (const client of clients) client.close();
    for (const journal of journals) journal.close();
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  });
  const journalPath = join(directory, 'trust.sqlite');
  const journal = openCardKeyJournal(journalPath); journals.push(journal);
  const options = { journal, origin, ca: readFileSync(certPath), ttlMs: 30, minimumIntervalMs: 5, timeoutMs: 150 };
  return { state, journal, options, directory, journalPath,
    resolver: changes => { const resolver = createFixedCardResolver({ ...options, ...changes }); clients.push(resolver); return resolver; } };
}

test('normal TLS, fixed origin/path/DID and coalesced fresh reads; caller cannot supply keys', async t => {
  const f = await fixture(t); const current = identity(); f.state.doc = current.doc;
  const resolver = f.resolver({ ttlMs: 500 });
  await assert.rejects(resolver.resolve('did:plc:' + 'a'.repeat(24)));
  assert.equal(f.state.calls, 0);
  f.state.wait = 20;
  const snapshots = await Promise.all(Array.from({ length: 12 }, () => resolver.resolve()));
  assert.equal(f.state.calls, 1);
  assert.ok(snapshots.every(value => value.generation === 1));
  assert.deepEqual(f.state.paths, ['/' + encodeURIComponent(fixedDid)]);
  snapshots[0].didDocument.verificationMethod[0].publicKeyMultibase = 'poison';
  assert.equal((await resolver.verify(current.options)).cardSignatureValid, true);
  await assert.rejects(resolver.verify({ ...current.options, trustedDidDocument: current.doc }));
  assert.equal(f.state.calls, 1);
  const noCa = f.resolver({ ca: undefined });
  await assert.rejects(noCa.resolve());
  assert.equal(f.state.calls, 1, 'untrusted TLS cannot reach HTTP handler');
});

test('rotation retires prior keys, revocation denies all, journal rejects rollback across restart', async t => {
  const f = await fixture(t); const a = identity(); const b = identity(); const c = identity();
  f.state.doc = a.doc;
  let resolver = f.resolver();
  assert.equal((await resolver.verify(a.options)).resolverGeneration, 1);
  f.state.doc = b.doc;
  assert.equal((await resolver.verify(a.options)).cardSignatureValid, true, 'documented bounded cache window');
  await delay(40);
  assert.equal((await resolver.verify(b.options)).resolverGeneration, 2);
  await assert.rejects(resolver.verify(a.options));
  const calls = f.state.calls;
  await assert.rejects(resolver.verify(a.options));
  assert.equal(f.state.calls, calls, 'bad signature does not force refresh');
  f.state.doc = { id: fixedDid, verificationMethod: [] };
  await delay(40); await assert.rejects(resolver.verify(b.options));
  assert.equal(f.journal.generation(), 3);
  f.state.doc = b.doc; await delay(10); await assert.rejects(resolver.verify(b.options));
  resolver.close(); f.journal.close();
  // Reopen the owner-only synthetic journal without any cache or live keys.
  const journal = openCardKeyJournal(f.journalPath);
  t.after(() => journal.close());
  resolver = f.resolver({ journal });
  f.state.doc = a.doc; await assert.rejects(resolver.verify(a.options));
  f.state.doc = c.doc; await delay(10);
  assert.equal((await resolver.verify(c.options)).resolverGeneration, 4);
  assert.equal(f.state.paths.every(path => path === '/' + encodeURIComponent(fixedDid)), true);
  if (process.env.VLPDS_EXP710_RESOLVER_EVIDENCE_PATH) writeFileSync(process.env.VLPDS_EXP710_RESOLVER_EVIDENCE_PATH,
    JSON.stringify({ result: 'rotation/revocation scenario PASS', did: fixedDid, source: 'Synthetic HTTPS authority; no public metadata queried',
      normalTlsVerifiedWithFixtureCa: true, fixedPathOnly: true, observedGenerations: [1, 2, 3, 4],
      priorKeyRetiredAfterRotation: true, keyRemovalRevokes: true, retiredKeyRollbackDeniedAcrossRestart: true,
      temporaryAuthorityOrigin: f.options.origin, oldKeyCacheWindowBoundedByTtl: true,
      badSignatureDoesNotForceResolution: true, noLiveKeysOrSettingsChanged: true }, null, 2));
});

test('no expired/stale fallback for outage, redirects, oversized or malformed metadata', async t => {
  const f = await fixture(t); const current = identity(); f.state.doc = current.doc;
  const resolver = f.resolver(); await resolver.verify(current.options);
  for (const mode of ['error', 'redirect', 'large', 'invalid', 'hang']) {
    f.state.mode = mode; await delay(40);
    await assert.rejects(resolver.verify(current.options));
  }
  f.state.mode = 'json'; f.state.doc = { ...current.doc, id: 'did:plc:' + 'a'.repeat(24) };
  await delay(10); await assert.rejects(resolver.verify(current.options));
  f.state.doc = current.doc; await delay(10);
  assert.equal((await resolver.verify(current.options)).cardSignatureValid, true, 'outages do not permanently retire good key');
});

test('deadlines, cooldown and operator invalidation prevent in-flight key resurrection', async t => {
  const f = await fixture(t); const current = identity(); f.state.doc = current.doc;
  const resolver = f.resolver({ timeoutMs: 40, minimumIntervalMs: 100 });
  f.state.wait = 100;
  await assert.rejects(resolver.resolve());
  const count = f.state.calls;
  await assert.rejects(resolver.resolve());
  assert.equal(f.state.calls, count);
  await delay(110); f.state.wait = 20;
  const pending = resolver.resolve();
  await delay(5); resolver.invalidate();
  await assert.rejects(pending);
  f.state.wait = 0; await delay(110);
  assert.equal((await resolver.verify(current.options)).cardSignatureValid, true);
});

test('concurrent journal generations and origin pins reject stale adoption or authority substitution', async t => {
  const f = await fixture(t); const a = identity(); const b = identity();
  const resolver = f.resolver(); f.state.doc = a.doc;
  await resolver.resolve();
  const oldGeneration = f.journal.generation();
  f.journal.adopt(b.doc.verificationMethod[0].publicKeyMultibase);
  assert.throws(() => f.journal.adopt(a.doc.verificationMethod[0].publicKeyMultibase, oldGeneration), /Concurrent/);
  assert.throws(() => f.journal.revoke(oldGeneration), /Concurrent/);
  assert.throws(() => f.resolver({ origin: 'https://unconfigured.invalid' }), /authority/);
  assert.throws(() => createFixedCardResolver({ ...f.options, origin: 'http://127.0.0.1' }));
  assert.throws(() => createFixedCardResolver({ ...f.options, origin: f.options.origin + '/other' }));
});
