// Local experimental Kody-compatible detached JWS. No network, repo/CAR import,
// live key access or implicit DID resolution. Trust pins are supplied separately.
import { createPublicKey, ECDH, sign, verify, createHash } from 'node:crypto';

export const identityExtension = 'urn:kody:experimental:a2a-agent-did:v0';
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const didPattern = /^did:plc:[a-z2-7]{24}$/;
const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

function base58(bytes) {
  let number = BigInt('0x' + Buffer.from(bytes).toString('hex'));
  let out = '';
  while (number) { out = alphabet[Number(number % 58n)] + out; number /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; out = '1' + out; }
  return out;
}

function fromBase58(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 128) throw new Error('Invalid Multikey');
  let number = 0n;
  for (const character of value) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error('Invalid Multikey');
    number = number * 58n + BigInt(digit);
  }
  let hex = number.toString(16); if (hex.length % 2) hex = '0' + hex;
  let bytes = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  for (const character of value) { if (character !== '1') break; bytes = Buffer.concat([Buffer.from([0]), bytes]); }
  if (base58(bytes) !== value) throw new Error('Noncanonical Multikey');
  return bytes;
}

export function publicMultibase(key) {
  const jwk = (key?.type === 'public' ? key : createPublicKey(key)).export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('P-256 key required');
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const compressed = ECDH.convertKey(point, 'prime256v1', undefined, undefined, 'compressed');
  return 'z' + base58(Buffer.concat([Buffer.from([0x80, 0x24]), compressed]));
}

function publicKey(multibase) {
  if (typeof multibase !== 'string' || !multibase.startsWith('z')) throw new Error('P-256 Multikey required');
  const bytes = fromBase58(multibase.slice(1));
  if (bytes.length !== 35 || bytes[0] !== 0x80 || bytes[1] !== 0x24 || ![2, 3].includes(bytes[2])) {
    throw new Error('P-256 Multikey required');
  }
  const point = ECDH.convertKey(bytes.subarray(2), 'prime256v1', undefined, undefined, 'uncompressed');
  return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') } });
}

function clean(value, depth = 0) {
  if (depth > 32) throw new Error('Card nesting exceeds limit');
  if (value === null || value === '') return null;
  if (Array.isArray(value)) {
    const items = value.map(item => clean(item, depth + 1)).filter(item => item !== null);
    return items.length ? items : null;
  }
  if (typeof value === 'object') {
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error('JSON-only card required');
    const entries = Object.entries(value).map(([key, item]) => [key, clean(item, depth + 1)]).filter(([, item]) => item !== null);
    return entries.length ? Object.fromEntries(entries) : null;
  }
  if (typeof value === 'number' && !Number.isFinite(value) || !['string', 'number', 'boolean'].includes(typeof value)) {
    throw new Error('JSON-only card required');
  }
  return value;
}

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export function unsignedCard(card) {
  if (!card || typeof card !== 'object' || Array.isArray(card)) throw new Error('Card object required');
  if (Buffer.byteLength(JSON.stringify(card)) > 8192) throw new Error('Card exceeds fixture limit');
  const { signatures: _ignored, ...unsigned } = card;
  const value = clean(unsigned);
  if (!value) throw new Error('Empty card');
  return value;
}

export function cardPayload(card) {
  return Buffer.from(canonical(unsignedCard(card)), 'utf8').toString('base64url');
}

function claimedDid(card) {
  const hints = card?.capabilities?.extensions?.filter(item => item?.uri === identityExtension);
  if (hints?.length !== 1 || !didPattern.test(hints[0]?.params?.did)) throw new Error('Exactly one synthetic agent DID required');
  return hints[0].params.did;
}

export function signLocalCard(card, privateKey) {
  if (Object.hasOwn(card, 'signatures')) throw new Error('Sign unsigned cards only');
  const did = claimedDid(card);
  // Enforce the curve before Node signs. This never writes a key.
  publicMultibase(privateKey);
  const protectedHeader = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JOSE', kid: did + '#card-signing' })).toString('base64url');
  const input = Buffer.from(protectedHeader + '.' + cardPayload(card));
  const bytes = sign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const s = BigInt('0x' + bytes.subarray(32).toString('hex'));
  if (s > order / 2n) Buffer.from((order - s).toString(16).padStart(64, '0'), 'hex').copy(bytes, 32);
  return { ...structuredClone(card), signatures: [{ protected: protectedHeader, signature: bytes.toString('base64url') }] };
}

function decoded(value, limit) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > limit) throw new Error('Invalid base64url');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) throw new Error('Noncanonical base64url');
  return bytes;
}

function loopbackUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.search || url.hash) {
    throw new Error('Exact loopback fixture URL required');
  }
  return url;
}

export function selectCardDocument(document, publisherDid) {
  if (!didPattern.test(publisherDid) || document?.id !== publisherDid || document.deactivated === true ||
      !Array.isArray(document.verificationMethod) || document.verificationMethod.length > 64) {
    throw new Error('Invalid trusted card DID document');
  }
  const methods = document.verificationMethod.filter(method => method?.id === publisherDid + '#card-signing');
  if (methods.length !== 1 || methods[0].controller !== publisherDid || methods[0].type !== 'Multikey') {
    throw new Error('Unique controlled trusted card-signing key required');
  }
  publicKey(methods[0].publicKeyMultibase);
  return { id: publisherDid, verificationMethod: [{ id: methods[0].id, controller: publisherDid,
    type: 'Multikey', publicKeyMultibase: methods[0].publicKeyMultibase }] };
}

export function verifyLocalSignedDiscovery({ publisherDid, record, card, trustedDidDocument, expectedCardUrl, expectedEndpoint }) {
  if (!didPattern.test(publisherDid)) throw new Error('Synthetic publisher DID required');
  const cardUrl = loopbackUrl(expectedCardUrl);
  const endpoint = loopbackUrl(expectedEndpoint);
  if (cardUrl.origin !== endpoint.origin || cardUrl.href !== expectedCardUrl || endpoint.href !== expectedEndpoint) {
    throw new Error('Pinned card and endpoint origin mismatch');
  }
  if (record?.uri !== `at://${publisherDid}/link.ident.agent/self` ||
      !exact(record.value, ['$type', 'agentCardUrl']) || record.value.$type !== 'link.ident.agent' ||
      record.value.agentCardUrl !== expectedCardUrl) throw new Error('Pointer publisher/singleton mismatch');
  const normalized = unsignedCard(card);
  if (claimedDid(normalized) !== publisherDid || trustedDidDocument?.id !== publisherDid) throw new Error('Publisher, advertised DID and trust pin disagree');
  const methods = selectCardDocument(trustedDidDocument, publisherDid).verificationMethod;
  const key = publicKey(methods[0].publicKeyMultibase);
  const faces = normalized.supportedInterfaces;
  if (faces?.length !== 1 || faces[0].url !== expectedEndpoint || faces[0].protocolBinding !== 'JSONRPC' ||
      faces[0].protocolVersion !== '1.0') throw new Error('Signed endpoint mismatch');
  if (!Array.isArray(card.signatures) || card.signatures.length !== 1 ||
      !exact(card.signatures[0], ['protected', 'signature'])) throw new Error('One detached signature required');
  const signature = card.signatures[0];
  const headerBytes = decoded(signature.protected, 1024);
  const header = JSON.parse(headerBytes.toString('utf8'));
  if (!exact(header, ['alg', 'typ', 'kid']) || header.alg !== 'ES256' || header.typ !== 'JOSE' ||
      header.kid !== publisherDid + '#card-signing' || headerBytes.toString('utf8') !== JSON.stringify(header)) {
    throw new Error('Invalid protected card header');
  }
  const bytes = decoded(signature.signature, 128);
  const input = Buffer.from(signature.protected + '.' + cardPayload(card));
  if (bytes.length !== 64 || !verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, bytes)) {
    throw new Error('Card signature rejected');
  }
  return { publisherDid, advertisedDid: publisherDid, cardKeyId: header.kid,
    cardSigningKey: 'did:key:' + methods[0].publicKeyMultibase, agentCardUrl: expectedCardUrl,
    endpoint: expectedEndpoint, cardSignatureValid: true, sameDidBinding: true,
    normalizedCard: normalized, payloadSha256: createHash('sha256').update(Buffer.from(cardPayload(card), 'base64url')).digest('hex'),
    repositoryProofVerifiedHere: false, principalEndorsementVerifiedHere: false,
    transportAuthenticated: false, authorizationGranted: false };
}
