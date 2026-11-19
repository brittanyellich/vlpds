import { readFile } from 'node:fs/promises';

export function entryAsset(html) {
  const match = html.match(/<script\b[^>]*\bsrc="(\/assets\/index-[A-Za-z0-9_-]+\.js)"/);
  if (!match) throw new Error('No hashed UI entry script found in HTML');
  return match[1];
}

export async function verifyPublicUi(origin, expected, fetcher = fetch) {
  const page = await fetcher(`${origin}/account/spaces`, { cache: 'no-store' });
  if (!page.ok) throw new Error(`Public account page returned ${page.status}`);
  const actual = entryAsset(await page.text());
  if (actual !== expected) throw new Error(`Public UI is stale: expected ${expected}, got ${actual}`);
  const asset = await fetcher(`${origin}${expected}`, { cache: 'no-store' });
  if (!asset.ok || !asset.headers.get('content-type')?.includes('javascript'))
    throw new Error(`Expected public UI asset is unavailable (${asset.status})`);
  await asset.body?.cancel();
  return actual;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    if (process.argv[2] === '--expected') console.log(entryAsset(await readFile(process.argv[3], 'utf8')));
    else if (process.argv[2] === '--public') console.log(await verifyPublicUi('https://pds.crate.social', process.argv[3]));
    else throw new Error('Usage: verify-ui.mjs --expected index.html | --public /assets/index-HASH.js');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
