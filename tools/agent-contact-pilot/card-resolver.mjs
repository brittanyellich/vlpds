// Fixed-authority metadata reads only. Never a general DID resolver, CAR reader,
// dispatcher, public handler or source of caller authorization.
import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { agentDid as fixedDid } from './pilot.mjs';
import { selectCardDocument, verifyLocalSignedDiscovery } from './signed-card.mjs';

export { fixedDid };
const fingerprint = text => createHash('sha256').update(text).digest('hex');
class MissingKey extends Error {}

export function openCardKeyJournal(path) {
  const db = new DatabaseSync(path);
  let closed = false;
  db.exec(`PRAGMA busy_timeout=1000; PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS card_key_history(fingerprint TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('active','retired'))) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS one_card_key ON card_key_history(state) WHERE state='active';
    CREATE TABLE IF NOT EXISTS card_resolver_meta(id INTEGER PRIMARY KEY CHECK(id=1), did TEXT NOT NULL, generation INTEGER NOT NULL, authority TEXT) STRICT;`);
  db.prepare('INSERT OR IGNORE INTO card_resolver_meta VALUES(1,?,0,NULL)').run(fixedDid);
  if (db.prepare('SELECT did FROM card_resolver_meta WHERE id=1').get().did !== fixedDid) {
    db.close(); throw new Error('Wrong DID key journal');
  }
  const generation = () => db.prepare('SELECT generation FROM card_resolver_meta WHERE id=1').get().generation;
  const transaction = fn => {
    db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); db.exec('COMMIT'); return result; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  };
  return {
    bindAuthority(origin) {
      transaction(() => {
        const current = db.prepare('SELECT authority FROM card_resolver_meta WHERE id=1').get().authority;
        if (current !== null && current !== origin) throw new Error('Key journal authority mismatch');
        db.prepare('UPDATE card_resolver_meta SET authority=? WHERE id=1').run(origin);
      });
    },
    adopt(multibase, expectedGeneration = generation()) {
      return transaction(() => {
        if (generation() !== expectedGeneration) throw new Error('Concurrent trust update; retry fresh resolution');
        const key = fingerprint(multibase);
        const previous = db.prepare('SELECT state FROM card_key_history WHERE fingerprint=?').get(key);
        if (previous?.state === 'retired') throw new Error('Retired card key cannot return automatically');
        if (previous?.state === 'active') return generation();
        if (db.prepare('SELECT count(*) AS count FROM card_key_history').get().count >= 64) throw new Error('Key journal capacity reached');
        db.prepare("UPDATE card_key_history SET state='retired' WHERE state='active'").run();
        db.prepare("INSERT INTO card_key_history VALUES(?,'active')").run(key);
        db.prepare('UPDATE card_resolver_meta SET generation=generation+1 WHERE id=1').run();
        return generation();
      });
    },
    revoke(expectedGeneration = generation()) {
      return transaction(() => {
        if (generation() !== expectedGeneration) throw new Error('Concurrent trust update; retry fresh resolution');
        const result = db.prepare("UPDATE card_key_history SET state='retired' WHERE state='active'").run();
        if (result.changes) db.prepare('UPDATE card_resolver_meta SET generation=generation+1 WHERE id=1').run();
        return generation();
      });
    },
    generation,
    close() { if (!closed) { closed = true; db.close(); } },
  };
}

function readDocument(url, agent, timeoutMs) {
  let timer;
  return new Promise((resolve, reject) => {
    const request = https.get(url, { agent, headers: { accept: 'application/json' } }, response => {
      if ([404, 410].includes(response.statusCode)) { response.destroy(); return reject(new MissingKey('Authoritative DID absent')); }
      const mediaType = response.headers['content-type']?.split(';')[0].trim().toLowerCase();
      if (response.statusCode !== 200 || !['application/json', 'application/did+ld+json'].includes(mediaType) ||
          response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity' ||
          Number(response.headers['content-length']) > 32768) {
        response.destroy(); return reject(new Error('Invalid trusted resolver response'));
      }
      let size = 0; const chunks = [];
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 32768) response.destroy(new Error('DID response too large'));
        else chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('aborted', () => reject(new Error('DID response aborted')));
      response.on('end', () => {
        try { resolve(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
        catch { reject(new Error('Invalid DID JSON')); }
      });
    });
    timer = setTimeout(() => {
      const error = new Error('DID resolution deadline');
      request.destroy(error); reject(error);
    }, timeoutMs);
    request.on('error', reject);
  }).finally(() => clearTimeout(timer));
}

export function createFixedCardResolver({ journal, origin = 'https://plc.directory', ca,
  ttlMs = 5000, minimumIntervalMs = 1000, timeoutMs = 3000 } = {}) {
  const base = new URL(origin);
  if (base.protocol !== 'https:' || base.origin !== origin || base.username || base.password || base.search || base.hash) {
    throw new Error('Exact operator-configured HTTPS resolver origin required');
  }
  if (!journal || !Number.isInteger(ttlMs) || ttlMs < 1 || ttlMs > 5000 ||
      !Number.isInteger(minimumIntervalMs) || minimumIntervalMs < 1 || minimumIntervalMs > 5000 ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) throw new Error('Bounded resolver policy required');
  journal.bindAuthority(origin);
  const target = new URL('/' + encodeURIComponent(fixedDid), origin);
  // Normal certificate and hostname validation; no redirect/proxy machinery or
  // rejectUnauthorized override. Optional CA is scoped to a fixture/operator.
  const agent = new https.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1, ...(ca ? { ca } : {}) });
  let cached; let inFlight; let epoch = 0; let nextRead = -Infinity; let closed = false;
  const current = snapshot => !closed && snapshot && snapshot.epoch === epoch &&
    snapshot.generation === journal.generation() && performance.now() < snapshot.expires;
  const view = snapshot => {
    if (!current(snapshot)) throw new Error('Resolution snapshot no longer current');
    return structuredClone({ didDocument: snapshot.document,
      generation: snapshot.generation, keyFingerprint: snapshot.fingerprint, fetchedAt: snapshot.fetchedAt });
  };
  async function resolve(did = fixedDid) {
    if (did !== fixedDid) throw new Error('Only fixed configured DID may resolve');
    if (closed) throw new Error('Resolver closed');
    if (current(cached)) return view(cached);
    if (inFlight) return view(await inFlight);
    if (performance.now() < nextRead) throw new Error('Resolver refresh cooldown; no stale fallback');
    cached = undefined;
    nextRead = performance.now() + minimumIntervalMs;
    const readEpoch = epoch;
    const readGeneration = journal.generation();
    inFlight = (async () => {
      try {
        const raw = await readDocument(target, agent, timeoutMs);
        if (closed || epoch !== readEpoch) throw new Error('Resolution invalidated while reading');
        if (raw && Object.hasOwn(raw, 'deactivated') && typeof raw.deactivated !== 'boolean') throw new Error('Invalid deactivation metadata');
        if (raw?.id === fixedDid && (raw.deactivated === true || raw.verificationMethod === undefined ||
            Array.isArray(raw.verificationMethod) && !raw.verificationMethod.some(method => method?.id === fixedDid + '#card-signing'))) {
          throw new MissingKey('Card key removed');
        }
        const document = selectCardDocument(raw, fixedDid);
        const key = document.verificationMethod[0].publicKeyMultibase;
        const generation = journal.adopt(key, readGeneration);
        cached = { document, generation, epoch, fingerprint: fingerprint(key),
          expires: performance.now() + ttlMs, fetchedAt: new Date().toISOString() };
        return cached;
      } catch (error) {
        cached = undefined;
        // A late/invalidated read may not revoke newer state either.
        if (!closed && epoch === readEpoch && error instanceof MissingKey) journal.revoke(readGeneration);
        throw error;
      }
    })();
    try { return view(await inFlight); } finally { inFlight = undefined; }
  }
  return {
    resolve,
    async verify(options) {
      if (options.publisherDid !== fixedDid || Object.hasOwn(options, 'trustedDidDocument')) throw new Error('Caller cannot choose DID or trusted keys');
      const snapshot = await resolve();
      const result = verifyLocalSignedDiscovery({ ...options, trustedDidDocument: snapshot.didDocument });
      if (!current(cached) || cached.generation !== snapshot.generation || cached.fingerprint !== snapshot.keyFingerprint) {
        throw new Error('Trust snapshot expired or changed before use');
      }
      return { ...result, resolverGeneration: snapshot.generation, resolverFetchedAt: snapshot.fetchedAt,
        authority: origin, trustMode: 'Fixed HTTPS authority plus local monotonic observed-key journal; not PLC operation-log verification' };
    },
    // Operator-side only; never bind to request fields or a public route.
    invalidate() { epoch++; cached = undefined; },
    close() { closed = true; epoch++; cached = undefined; agent.destroy(); },
  };
}
