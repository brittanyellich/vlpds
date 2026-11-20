// Test-only IPC worker. No real DID/key/token lookup. Public key pins leave by
// the parent's private pipe before HTTP discovery; the private key never leaves.
import { createServer } from 'node:http';
import { createHash, generateKeyPairSync, timingSafeEqual, randomUUID } from 'node:crypto';
import { signLocalCard, publicMultibase, identityExtension, verifyLocalSignedDiscovery } from '../signed-card.mjs';

let size = 0; const chunks = [];
for await (const chunk of process.stdin) {
  size += chunk.length; if (size > 32768) throw new Error('Fixture IPC too large'); chunks.push(chunk);
}
const config = JSON.parse(Buffer.concat(chunks).toString('utf8'));
if (process.argv[2] === 'verify') {
  try { console.log(JSON.stringify({ ok: true, result: verifyLocalSignedDiscovery(config) })); }
  catch { console.log(JSON.stringify({ ok: false, error: 'Signed discovery rejected' })); }
} else if (process.argv[2] === 'serve') {
  const { agentDid, principalDid, token } = config;
  if (![agentDid, principalDid].every(did => /^did:plc:[a-z2-7]{24}$/.test(did)) ||
      typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) throw new Error('Synthetic fixture config required');
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const document = { id: agentDid, verificationMethod: [{ id: agentDid + '#card-signing', controller: agentDid,
    type: 'Multikey', publicKeyMultibase: publicMultibase(privateKey) }] };
  const path = `/agents/${encodeURIComponent(agentDid)}`;
  let card;
  const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  const digest = text => createHash('sha256').update(text).digest();
  const server = createServer({ requestTimeout: 5000 }, async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
    if (req.method === 'GET' && req.url === path + '/.well-known/agent-card.json') return send(200, card);
    if (req.method !== 'POST' || req.url !== path + '/a2a/v1') return send(404, { error: 'Not found' });
    if (!timingSafeEqual(digest(req.headers.authorization ?? ''), digest('Bearer ' + token))) return send(401, { error: 'Fixture authentication required' });
    if (req.headers['content-type']?.split(';')[0] !== 'application/json' || req.headers['a2a-version'] !== '1.0') return send(400, { error: 'A2A1 JSON required' });
    try {
      let length = 0; const body = [];
      for await (const chunk of req.iterator({ destroyOnReturn: false })) {
        length += chunk.length; if (length > 4096) { res.setHeader('connection', 'close'); return send(413, { error: 'Too large' }); } body.push(chunk);
      }
      const rpc = JSON.parse(Buffer.concat(body).toString('utf8'));
      const message = rpc.params?.message;
      const data = message?.parts?.[0]?.data;
      if (!exact(rpc, ['jsonrpc', 'id', 'method', 'params']) || rpc.jsonrpc !== '2.0' ||
          typeof rpc.id !== 'string' || rpc.id.length < 1 || rpc.id.length > 128 || rpc.method !== 'SendMessage' ||
          !exact(rpc.params, ['message']) || !exact(message, ['messageId', 'role', 'parts']) ||
          message.role !== 'ROLE_USER' || typeof message.messageId !== 'string' || message.messageId.length < 1 ||
          message.messageId.length > 128 || !Array.isArray(message.parts) || message.parts.length !== 1 ||
          !exact(message.parts[0], ['data']) || !exact(data, ['skillId', 'agentDid', 'principalDid']) ||
          data.skillId !== 'resolve-identity-fixture' || data.agentDid !== agentDid || data.principalDid !== principalDid) {
        return send(400, { error: 'Fixed synthetic skill only' });
      }
      return send(200, { jsonrpc: '2.0', id: rpc.id, result: { message: { role: 'ROLE_AGENT',
        messageId: randomUUID(), contextId: randomUUID(), parts: [{ data: { agentDid, principalDid, status: 'declared_unverified' } }] } } });
    } catch { return send(400, { error: 'Invalid fixture request' }); }
  });
  server.listen(0, '127.0.0.1', () => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const endpoint = origin + path + '/a2a/v1';
    const cardUrl = origin + path + '/.well-known/agent-card.json';
    card = signLocalCard({ name: 'Synthetic same-DID identity fixture', version: '0.1.0-local',
      supportedInterfaces: [{ url: endpoint, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
      capabilities: { streaming: false, pushNotifications: false,
        extensions: [{ uri: identityExtension, params: { did: agentDid } },
          { uri: 'urn:atagents:exp-710:synthetic-bearer:v1', required: true,
            params: { scheme: 'Bearer', purpose: 'Operator-provided disposable fixture token only' } }] },
      defaultInputModes: ['application/json'], defaultOutputModes: ['application/json'],
      skills: [{ id: 'resolve-identity-fixture', name: 'Resolve synthetic pair', tags: ['read-only'],
        description: 'Synthetic fixture only; no Kody dispatch or endorsement verifier' }],
    }, privateKey);
    const alternate = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    console.log(JSON.stringify({ agentDid, principalDid, origin, cardUrl, endpoint, trustedDidDocument: document,
      alternatePublicKeyForSubstitutionTest: publicMultibase(alternate.privateKey) }));
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => server.close());
} else throw new Error('Fixture mode required');
