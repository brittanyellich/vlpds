import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { signLocalCard, publicMultibase, cardPayload, unsignedCard, identityExtension,
  verifyLocalSignedDiscovery } from './signed-card.mjs';

const did = 'did:plc:' + 'a'.repeat(24);
const otherDid = 'did:plc:' + 'b'.repeat(24);
function setup() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const cardUrl = 'http://127.0.0.1:32123/agent-card.json';
  const endpoint = 'http://127.0.0.1:32123/a2a/v1';
  const card = signLocalCard({ name: 'Synthetic signed card', version: '0.1.0',
    supportedInterfaces: [{ url: endpoint, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    capabilities: { streaming: false, extensions: [{ uri: identityExtension, params: { did } }] },
    defaultInputModes: ['application/json'], defaultOutputModes: ['application/json'],
    skills: [{ id: 'resolve-identity-fixture', name: 'Synthetic read only' }],
  }, pair.privateKey);
  const trust = { id: did, verificationMethod: [{ id: did + '#card-signing', controller: did,
    type: 'Multikey', publicKeyMultibase: publicMultibase(pair.privateKey) }] };
  const options = { publisherDid: did, record: { uri: `at://${did}/link.ident.agent/self`,
    value: { $type: 'link.ident.agent', agentCardUrl: cardUrl } }, card, trustedDidDocument: trust,
    expectedCardUrl: cardUrl, expectedEndpoint: endpoint };
  return { pair, options };
}

test('same publisher DID, advertised DID, controlled key and signed endpoint agree under independent pin', () => {
  const { options } = setup();
  const result = verifyLocalSignedDiscovery(options);
  assert.equal(result.cardSignatureValid, true);
  assert.equal(result.sameDidBinding, true);
  assert.equal(result.cardKeyId, did + '#card-signing');
  assert.equal(result.transportAuthenticated, false);
  assert.equal(result.authorizationGranted, false);
  assert.equal(result.repositoryProofVerifiedHere, false);
  assert.ok(result.cardSigningKey.startsWith('did:key:z'));
});

test('publisher, singleton, claimed DID, key controller and trusted key substitutions fail', () => {
  const mutate = [
    value => { value.publisherDid = otherDid; },
    value => { value.record.uri = value.record.uri.replace('/self', '/other'); },
    value => { value.record.value.agentCardUrl = 'http://127.0.0.1:9999/card'; },
    value => { value.card.capabilities.extensions[0].params.did = otherDid; },
    value => { value.card.capabilities.extensions.push(structuredClone(value.card.capabilities.extensions[0])); },
    value => { value.trustedDidDocument.id = otherDid; },
    value => { value.trustedDidDocument.verificationMethod[0].controller = otherDid; },
    value => { value.trustedDidDocument.verificationMethod[0].id = did + '#other'; },
    value => { value.trustedDidDocument.verificationMethod.push(structuredClone(value.trustedDidDocument.verificationMethod[0])); },
    value => { value.trustedDidDocument.verificationMethod[0].publicKeyMultibase = publicMultibase(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey); },
  ];
  for (const change of mutate) { const { options } = setup(); change(options); assert.throws(() => verifyLocalSignedDiscovery(options)); }
});

test('payload, endpoint, protected header and signature tampering fail closed', () => {
  const changes = [
    value => { value.card.name = 'Tampered'; },
    value => { value.card.supportedInterfaces[0].url = 'http://127.0.0.1:9999/a2a/v1'; },
    value => { value.card.skills[0].id = 'arbitrary-code'; },
    value => { delete value.card.signatures; },
    value => { value.card.signatures[0].signature += '='; },
    value => { const bytes = Buffer.from(value.card.signatures[0].signature, 'base64url'); bytes[0] ^= 1; value.card.signatures[0].signature = bytes.toString('base64url'); },
    value => { const head = JSON.parse(Buffer.from(value.card.signatures[0].protected, 'base64url')); head.alg = 'none'; value.card.signatures[0].protected = Buffer.from(JSON.stringify(head)).toString('base64url'); },
    value => { const head = JSON.parse(Buffer.from(value.card.signatures[0].protected, 'base64url')); head.jku = 'https://evil.test/key'; value.card.signatures[0].protected = Buffer.from(JSON.stringify(head)).toString('base64url'); },
    value => { value.expectedEndpoint = 'http://127.0.0.1:9999/a2a/v1'; },
    value => { value.expectedCardUrl = 'https://public.test/card'; },
  ];
  for (const change of changes) { const { options } = setup(); change(options); assert.throws(() => verifyLocalSignedDiscovery(options)); }
});

test('clean-empty canonicalization matches convention and returns only the signed normalized view', () => {
  const { pair, options } = setup();
  const base = unsignedCard(options.card);
  const extended = { ...base, empty: '', object: {}, list: [null, '', {}, []], nested: { a: null, b: '' } };
  assert.equal(cardPayload(base), cardPayload(extended));
  options.card = signLocalCard(extended, pair.privateKey);
  const result = verifyLocalSignedDiscovery(options);
  assert.deepEqual(result.normalizedCard, base);
  let nested = {}; let root = nested;
  for (let i = 0; i < 40; i++) { root.child = {}; root = root.child; }
  assert.throws(() => cardPayload(nested), /nesting/);
  assert.throws(() => cardPayload({ invalid: Infinity }));
});

test('safe optional Kody canonicalize/ATProto crypto crosscheck without importing CAR verifier', {
  skip: !process.env.KODY_CANONICALIZE_MODULE || !process.env.KODY_CRYPTO_MODULE,
}, async () => {
  const canonicalize = (await import(pathToFileURL(process.env.KODY_CANONICALIZE_MODULE))).default;
  const crypto = await import(pathToFileURL(process.env.KODY_CRYPTO_MODULE));
  const { pair, options } = setup();
  assert.equal(Buffer.from(canonicalize(unsignedCard(options.card))).toString('base64url'), cardPayload(options.card));
  const header = options.card.signatures[0].protected;
  const input = Buffer.from(header + '.' + cardPayload(options.card));
  const publicDidKey = 'did:key:' + publicMultibase(pair.privateKey);
  assert.equal(await crypto.verifySignature(publicDidKey, input, Buffer.from(options.card.signatures[0].signature, 'base64url')), true);
  const privateJwk = pair.privateKey.export({ format: 'jwk' });
  const atprotoKey = await crypto.P256Keypair.import(Buffer.from(privateJwk.d, 'base64url'));
  assert.equal(atprotoKey.did(), publicDidKey);
  assert.equal(verify('sha256', input, { key: pair.publicKey, dsaEncoding: 'ieee-p1363' }, await atprotoKey.sign(input)), true);
  assert.equal(sign('sha256', input, { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).length, 64);
});
