import assert from 'node:assert/strict';
import { test } from 'node:test';
import { entryAsset, verifyPublicUi } from '../scripts/verify-ui.mjs';

const expected = '/assets/index-NEW123.js';
test('rejects stale HTML', async () => {
  assert.equal(entryAsset(`<script type="module" src="${expected}"></script>`), expected);
  await assert.rejects(verifyPublicUi('https://pds.example', expected,
    async () => new Response('<script src="/assets/index-OLD123.js"></script>')), /stale/);
});
test('rejects missing asset', async () => {
  const fetcher = async (url) => url.endsWith('.js') ? new Response('', { status: 404 }) : new Response(`<script src="${expected}"></script>`);
  await assert.rejects(verifyPublicUi('https://pds.example', expected, fetcher), /unavailable/);
});
test('accepts matching HTML and JavaScript', async () => {
  const fetcher = async (url) => url.endsWith('.js')
    ? new Response('console.log(1)', { headers: { 'content-type': 'text/javascript' } })
    : new Response(`<script src="${expected}"></script>`);
  assert.equal(await verifyPublicUi('https://pds.example', expected, fetcher), expected);
});
