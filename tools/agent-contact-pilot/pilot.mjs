import { createServer } from 'node:http';
import { createHash, createPublicKey, randomUUID, sign, verify } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

export const agentDid = 'did:plc:6tlvgafuonoighfrtpejff5m';
export const principalDid = 'did:plc:exquicw7jew5vxerpgvc3x6w';
export const skillId = 'resolve-identity-test';
export const agentPath = `/agents/${encodeURIComponent(agentDid)}/a2a/v1`;
export const cardPath = `/agents/${encodeURIComponent(agentDid)}/.well-known/agent-card.json`;
export const fixedData = Object.freeze({ skillId, agentDid, principalDid });
const maxBody = 4096;
const maxAge = 60_000;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const label = value => typeof value === 'string' && /^[a-zA-Z0-9._:-]{1,128}$/.test(value);

class PilotError extends Error {
  constructor(status, message, rpcCode = status === 400 ? -32602 : -32000) {
    super(message); this.status = status; this.rpcCode = rpcCode;
  }
}

export function signatureBytes({ sender, keyId, audience, path, body, timestamp, nonce }) {
  return Buffer.from(JSON.stringify(['atagents/exp-710-local-request', 1, sender, keyId,
    audience, 'POST', path, hash(body), timestamp, nonce]), 'utf8');
}

// Test/operator helper. This does not provision a key or change any account.
export function signedHeaders(privateKey, { sender, keyId, audience, body, path = agentPath,
  timestamp = new Date().toISOString(), nonce = randomUUID() }) {
  return {
    'content-type': 'application/json', 'a2a-version': '1.0',
    'x-agent-sender': sender, 'x-agent-key-id': keyId,
    'x-agent-audience': audience,
    'x-agent-timestamp': timestamp, 'x-agent-nonce': nonce,
    'x-agent-signature': sign(null, signatureBytes({ sender, keyId, audience, path, body, timestamp, nonce }), privateKey).toString('base64'),
  };
}

export function fixedRequest(messageId = randomUUID(), id = messageId) {
  return { jsonrpc: '2.0', id, method: 'SendMessage', params: { message: {
    messageId, role: 'ROLE_USER', parts: [{ data: { ...fixedData } }],
  } } };
}

export function validateRequest(rpc) {
  if (!exact(rpc, ['jsonrpc', 'id', 'method', 'params']) || rpc.jsonrpc !== '2.0' ||
      !(typeof rpc.id === 'string' && rpc.id.length > 0 && rpc.id.length <= 128 || Number.isSafeInteger(rpc.id))) {
    throw new PilotError(400, 'Invalid JSON-RPC envelope', -32600);
  }
  if (rpc.method !== 'SendMessage') throw new PilotError(400, 'Only SendMessage is supported', -32601);
  const message = rpc.params?.message;
  const part = message?.parts?.[0];
  if (!exact(rpc.params, ['message']) || !exact(message, ['messageId', 'role', 'parts']) ||
      !label(message.messageId) || message.role !== 'ROLE_USER' ||
      !Array.isArray(message.parts) || message.parts.length !== 1 ||
      !(exact(part, ['data']) || exact(part, ['data', 'mediaType']) && part.mediaType === 'application/json') ||
      !exact(part.data, ['skillId', 'agentDid', 'principalDid']) ||
      !Object.entries(fixedData).every(([key, value]) => part.data[key] === value)) {
    throw new PilotError(400, 'Only the fixed read-only skill and identity pair are supported');
  }
  return message.messageId;
}

function safeResult(value) {
  if (!value || value.agentDid !== agentDid || value.principalDid !== principalDid ||
      !['verified', 'declared_unverified', 'no_declaration'].includes(value.status)) {
    throw new Error('Invalid resolver result');
  }
  // No raw Kody errors, reason strings, credentials, or unrecognized fields.
  return { agentDid, principalDid, status: value.status };
}

// The only outbound target is an operator-configured IPv4 loopback endpoint.
// It is not authenticated by the Kody server; this adapter claims no such auth.
export function kodyDispatch(endpoint, { timeoutMs = 75_000 } = {}) {
  const url = new URL(endpoint);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' ||
      url.pathname !== '/a2a/v1' || url.username || url.password || url.search || url.hash) {
    throw new Error('Configure an exact http://127.0.0.1:port/a2a/v1 Kody endpoint');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 90_000) throw new Error('Invalid dispatch timeout');
  return async messageId => {
    const response = await fetch(url, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
      headers: { 'content-type': 'application/json', 'a2a-version': '1.0' },
      body: JSON.stringify(fixedRequest(messageId)),
    });
    if (!response.ok || response.headers.get('content-type')?.split(';')[0] !== 'application/json') {
      await response.body?.cancel();
      throw new Error('Dispatch unavailable');
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maxBody) throw new Error('Dispatch response too large');
      chunks.push(chunk);
    }
    const rpc = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (rpc.jsonrpc !== '2.0' || rpc.id !== messageId || rpc.error ||
        rpc.result?.message?.role !== 'ROLE_AGENT' || !label(rpc.result.message.messageId) ||
        !label(rpc.result.message.contextId) || rpc.result.message.parts?.length !== 1) {
      throw new Error('Dispatch failed');
    }
    return safeResult(rpc.result.message.parts[0].data);
  };
}

export function openLedger(path) {
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=1000;
    CREATE TABLE IF NOT EXISTS requests(sender TEXT NOT NULL, message_id TEXT NOT NULL,
      input_hash TEXT NOT NULL, state TEXT NOT NULL, result TEXT,
      PRIMARY KEY(sender,message_id)) STRICT;
    CREATE TABLE IF NOT EXISTS nonces(sender TEXT NOT NULL, nonce TEXT NOT NULL,
      seen_at INTEGER NOT NULL, PRIMARY KEY(sender,nonce)) STRICT;`);
  return {
    reserve(sender, nonce, messageId, bytes, now) {
      db.exec('BEGIN IMMEDIATE');
      try {
        db.prepare('DELETE FROM nonces WHERE seen_at < ?').run(now - maxAge * 2);
        if (db.prepare('SELECT 1 FROM nonces WHERE sender=? AND nonce=?').get(sender, nonce)) {
          throw new PilotError(401, 'Replayed authentication');
        }
        db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(sender, nonce, now);
        const previous = db.prepare('SELECT * FROM requests WHERE sender=? AND message_id=?').get(sender, messageId);
        if (previous && previous.input_hash !== hash(bytes)) throw new PilotError(409, 'Message ID conflict');
        if (db.prepare('SELECT count(*) AS count FROM nonces WHERE sender=?').get(sender).count > 4096 ||
            !previous && db.prepare('SELECT count(*) AS count FROM requests WHERE sender=?').get(sender).count >= 1000) {
          throw new PilotError(429, 'Local pilot ledger capacity reached');
        }
        if (!previous) db.prepare('INSERT INTO requests VALUES(?,?,?,\'pending\',NULL)').run(sender, messageId, hash(bytes));
        db.exec('COMMIT');
        return previous;
      } catch (error) { db.exec('ROLLBACK'); throw error; }
    },
    finish(sender, messageId, result) {
      db.prepare('UPDATE requests SET state=\'done\',result=? WHERE sender=? AND message_id=?')
        .run(JSON.stringify(result), sender, messageId);
    },
    close() { db.close(); },
  };
}

function trustedKeys(senders) {
  const keys = new Map();
  if (!Array.isArray(senders) || senders.length < 1 || senders.length > 8) throw new Error('Configure 1–8 local sender pins');
  for (const { sender, keyId, publicKeyPem } of senders) {
    if (!label(sender) || !label(keyId)) throw new Error('Invalid sender pin');
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519' || keys.has(`${sender}/${keyId}`)) throw new Error('Invalid/duplicate sender key');
    keys.set(`${sender}/${keyId}`, key);
  }
  return keys;
}

function authenticate(req, body, keys, expectedAudience) {
  const names = ['x-agent-sender', 'x-agent-key-id', 'x-agent-timestamp', 'x-agent-nonce', 'x-agent-signature', 'x-agent-audience'];
  for (const name of names) {
    if (req.rawHeaders.filter((_, i) => i % 2 === 0 && req.rawHeaders[i].toLowerCase() === name).length !== 1) {
      throw new PilotError(401, 'Authentication required');
    }
  }
  const [sender, keyId, timestamp, nonce, encoded, audience] = names.map(name => req.headers[name]);
  const key = keys.get(`${sender}/${keyId}`);
  const signature = Buffer.from(encoded, 'base64');
  const now = Date.now();
  if (!key || audience !== expectedAudience || !label(sender) || !label(keyId) || !label(nonce) ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(timestamp) ||
      !Number.isFinite(Date.parse(timestamp)) || Math.abs(now - Date.parse(timestamp)) > maxAge ||
      signature.length !== 64 || signature.toString('base64') !== encoded ||
      !verify(null, signatureBytes({ sender, keyId, audience, path: req.url, body, timestamp, nonce }), key, signature)) {
    throw new PilotError(401, 'Authentication required');
  }
  return { sender, nonce, now };
}

function card(origin) {
  return {
    name: 'One-agent identity resolver (local EXP-710)', version: '0.1.0-local',
    description: 'Authenticated local fixed-pair read-only resolver; no general task execution.',
    supportedInterfaces: [{ url: origin + agentPath, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    defaultInputModes: ['application/json'], defaultOutputModes: ['application/json'],
    capabilities: { streaming: false, pushNotifications: false, extensions: [{
      uri: 'urn:atagents:exp-710:local-request-signature:v1', required: true,
      description: 'Operator-pinned Ed25519 request signatures required; see local README.',
      params: { agentDid, principalDid, identityHint: 'unverified; resolve skill returns endorsement status' },
    }] },
    // This is explicitly a custom local authentication profile, not OAuth or a
    // fabricated A2A standard security scheme. The required extension names it.
    skills: [{ id: skillId, name: 'Resolve fixed identity pair',
      description: 'Resolve only the configured agent and principal; result is not a tool grant.',
      tags: ['read-only', 'identity'] }],
  };
}

export function contactPointer(origin, { optedIn = false } = {}) {
  if (!optedIn) return undefined;
  const url = new URL(origin);
  if (url.origin !== origin || url.protocol !== 'http:' || url.hostname !== '127.0.0.1') throw new Error('Local pointer only');
  // Local JSON draft only, never a repo write. No XRPC contactUrl is advertised
  // because this implementation exposes only the A2A binding.
  return { agentCardUrl: origin + cardPath };
}

export function createPilot({ enabled = false, senders, ledger, dispatch, maxConcurrent = 1, publicOrigin }) {
  const keys = trustedKeys(senders);
  if (!ledger || typeof dispatch !== 'function' || maxConcurrent !== 1) throw new Error('One bounded dispatcher and durable ledger required');
  if (publicOrigin !== undefined) {
    const url = new URL(publicOrigin);
    if (url.origin !== publicOrigin || url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
      throw new Error('Native mount audience must be an exact loopback origin');
    }
  }
  let busy = false;
  const server = createServer({ requestTimeout: 5000, headersTimeout: 3000 }, async (req, res) => {
    const send = (status, value) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(value));
    };
    if (!enabled) return send(404, { error: 'NotFound' });
    if (req.socket.remoteAddress !== '127.0.0.1') return send(403, { error: 'Loopback only' });
    if (req.method === 'GET' && req.url === cardPath) {
      return send(200, card(publicOrigin ?? `http://127.0.0.1:${server.address().port}`));
    }
    if (req.method !== 'POST' || req.url !== agentPath) return send(404, { error: 'NotFound' });
    let rpc;
    let authenticated = false;
    try {
      if (req.headers['content-type']?.split(';')[0] !== 'application/json') throw new PilotError(415, 'JSON required');
      const chunks = [];
      let size = 0;
      for await (const chunk of req.iterator({ destroyOnReturn: false })) {
        size += chunk.length;
        if (size > maxBody) throw new PilotError(413, 'Request too large');
        chunks.push(chunk);
      }
      const bytes = Buffer.concat(chunks);
      const auth = authenticate(req, bytes, keys, publicOrigin ?? `http://127.0.0.1:${server.address().port}`);
      authenticated = true;
      rpc = JSON.parse(bytes.toString('utf8'));
      if (req.headers['a2a-version'] !== '1.0') throw new PilotError(400, 'A2A 1.0 required', -32009);
      const messageId = validateRequest(rpc);
      // Hash only semantic message content: RPC id and JSON formatting can
      // differ on a legitimate retry; neither changes the fixed dispatch.
      const semantic = JSON.stringify(fixedRequest(messageId).params.message);
      if (busy) throw new PilotError(503, 'Dispatcher busy; retry same message ID');
      const previous = ledger.reserve(auth.sender, auth.nonce, messageId, semantic, auth.now);
      if (previous) {
        if (previous.state !== 'done') throw new PilotError(409, 'Prior dispatch outcome unresolved; no automatic retry');
        return send(200, { jsonrpc: '2.0', id: rpc.id, ...JSON.parse(previous.result) });
      }
      busy = true;
      let result;
      try {
        const data = safeResult(await dispatch(messageId));
        result = { result: { message: { role: 'ROLE_AGENT', messageId: randomUUID(), contextId: randomUUID(),
          parts: [{ data, mediaType: 'application/json' }] } } };
      } catch {
        result = { error: { code: -32603, message: 'Identity lookup failed; outcome not retried automatically' } };
      } finally { busy = false; }
      ledger.finish(auth.sender, messageId, result);
      return send(200, { jsonrpc: '2.0', id: rpc.id, ...result });
    } catch (error) {
      const status = error instanceof PilotError ? error.status : error instanceof SyntaxError ? 400 : 500;
      if (status === 413) res.setHeader('connection', 'close');
      const message = status === 500 ? 'Internal error' : error.message;
      if (authenticated) {
        const id = typeof rpc?.id === 'string' && rpc.id.length <= 128 || Number.isSafeInteger(rpc?.id) ? rpc.id : null;
        const code = error instanceof PilotError ? error.rpcCode : error instanceof SyntaxError ? -32700 : -32603;
        return send(status, { jsonrpc: '2.0', id, error: { code, message } });
      }
      return send(status, { error: message });
    }
  });
  // The CLI binds IPv4 loopback. Exported server tests do the same; this module
  // contains no PDS auto-registration, public listener, CAR parser, or keys.
  return server;
}
