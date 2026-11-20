// Local private-hop prototype. Distinct operator-owned sender key and ledger;
// never forward public caller credentials or caller-selected destinations.
import { agentPath, agentDid, principalDid, fixedRequest, signedHeaders } from './pilot.mjs';

export function signedPrivateDispatch(endpoint, { privateKey, sender, keyId, timeoutMs = 75000 } = {}) {
  const url = new URL(endpoint);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || Number(url.port) < 1024 ||
      url.pathname !== agentPath || url.username || url.password || url.search || url.hash) {
    throw new Error('Exact private loopback agent endpoint required');
  }
  if (!privateKey || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 75000) {
    throw new Error('Private sender key and bounded deadline required');
  }
  const audience = url.origin;
  return async messageId => {
    // Caller supplies only an already reserved event identifier. Fixed schema
    // and private peer identity are constructed here, never copied from input.
    const rpc = fixedRequest(messageId, messageId);
    const body = JSON.stringify(rpc);
    const headers = signedHeaders(privateKey, { sender, keyId, audience, body });
    const response = await fetch(url, { method: 'POST', headers, body,
      redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    const mediaType = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
    if (!response.ok || mediaType !== 'application/json') {
      await response.body?.cancel(); throw new Error('Private dispatch unavailable');
    }
    let size = 0; const chunks = [];
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > 4096) { await response.body.cancel().catch(() => {}); throw new Error('Private dispatch response too large'); }
      chunks.push(chunk);
    }
    let reply;
    try { reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
    catch { throw new Error('Invalid private dispatch JSON'); }
    const message = reply?.result?.message;
    const data = message?.parts?.[0]?.data;
    if (reply?.jsonrpc !== '2.0' || reply?.id !== messageId || reply?.error || message?.role !== 'ROLE_AGENT' ||
        typeof message?.contextId !== 'string' || !message.contextId || !Array.isArray(message?.parts) || message.parts.length !== 1 ||
        data?.agentDid !== agentDid || data?.principalDid !== principalDid ||
        !['verified', 'declared_unverified', 'no_declaration'].includes(data?.status)) {
      throw new Error('Invalid private dispatch correlation');
    }
    return { agentDid, principalDid, status: data.status };
  };
}
