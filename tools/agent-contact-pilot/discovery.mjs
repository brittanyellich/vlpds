import { agentDid, principalDid, cardPath, agentPath, skillId } from './pilot.mjs';

export const endorsementUri = `at://${principalDid}/link.ident.endorsement/${agentDid}`;
export const contactUri = `at://${agentDid}/link.ident.agent/self`;

// Fixture discovery, deliberately independent of endorsement authentication.
// A JSON getRecord-shaped object is not proof of repo authorship/current head.
// No CAR parsing or arbitrary remote fetch is performed by this helper.
export async function discoverLocalContact({ origin, readRecord, readCard }) {
  const url = new URL(origin);
  if (url.origin !== origin || url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
    throw new Error('Local fixture origin required');
  }
  const endorsement = await readRecord(endorsementUri);
  if (endorsement?.uri !== endorsementUri || endorsement.value?.$type !== 'link.ident.endorsement' ||
      endorsement.value.agent !== agentDid) throw new Error('Endorsement fixture mismatch');
  const contact = await readRecord(contactUri);
  if (contact?.uri !== contactUri || contact.value?.$type !== 'link.ident.agent' ||
      contact.value.agentCardUrl !== origin + cardPath ||
      Object.keys(contact.value).some(key => !['$type', 'agentCardUrl'].includes(key))) {
    throw new Error('Contact singleton fixture mismatch');
  }
  // The expected URL is pinned by the operator's origin, never an arbitrary URL
  // obtained from the record. readCard must use no redirects and bounded JSON.
  const card = await readCard(origin + cardPath);
  const face = card?.supportedInterfaces?.[0];
  const hint = card?.capabilities?.extensions?.[0]?.params;
  if (card.supportedInterfaces.length !== 1 || face?.url !== origin + agentPath ||
      face.protocolBinding !== 'JSONRPC' || face.protocolVersion !== '1.0' ||
      card.skills?.length !== 1 || card.skills[0].id !== skillId ||
      hint?.agentDid !== agentDid || hint.principalDid !== principalDid) {
    throw new Error('Agent Card fixture mismatch');
  }
  return { principalDid, agentDid, endorsementUri, contactUri, agentCardUrl: origin + cardPath,
    endpoint: face.url, endorsementVerified: false, authorizationGranted: false,
    evidence: 'Local fixture discovery only; use separate authenticated Kody endorsement result' };
}
