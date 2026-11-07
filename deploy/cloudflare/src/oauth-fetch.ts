// Bound untrusted discovery/authorization JSON before SDK schema validation.
// Zod 3 (required by the current SDK) has an outstanding collection-size advisory.
const MAX_BYTES = 64 * 1024;
export function validateJsonSize(value: unknown): void {
  let count = 0;
  const visit = (v: unknown, depth: number) => {
    if (++count > 2048 || depth > 20) throw new Error('OAuth response too complex');
    if (v && typeof v === 'object') {
      const values = Object.values(v);
      if (values.length > 128) throw new Error('OAuth collection too large');
      for (const item of values) visit(item, depth + 1);
    }
  };
  visit(value, 0);
}
export const oauthFetch: typeof fetch = async (input, init) => {
  const request = new Request(input, {...init, redirect:'manual'});
  if (new URL(request.url).protocol !== 'https:') throw new Error('HTTPS required');
  const response = await fetch(request, {redirect:'manual', signal:AbortSignal.any([request.signal, AbortSignal.timeout(15000)])});
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new Error('OAuth redirects are not allowed');
  }
  const reader = response.body?.getReader();
  if (!reader) return response;
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const {value, done} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) throw new Error('OAuth response too large');
      chunks.push(value);
    }
  } catch (error) { await reader.cancel(); throw error; }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  if (size) {
    // All SDK endpoints here return JSON. Reject other formats before validation.
    validateJsonSize(JSON.parse(new TextDecoder().decode(bytes)));
  }
  const result = new Response(size ? bytes : null, {status:response.status, statusText:response.statusText, headers:response.headers});
  Object.defineProperty(result, 'url', {value:response.url});
  return result;
};
