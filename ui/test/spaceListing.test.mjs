import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canDeactivateOld, copyPendingSpaces, isMigrationDone, listSpaceRefs, receiptsForRetry } from '../src/pages/migrate/spaceListing.mjs'

const uri = 'at:space/did:plc:exquicw7jew5vxerpgvc3x6w/com.example.group/main'
const legacy = uri.replace(/^at:space\/([^/]+)\//, 'at://$1/space/')
const other = uri.replace(/main$/, 'other')
const fixture = (spaces) => listSpaceRefs(async () => ({ spaces }), 100)

test('retains usable references in mixed listings and deduplicates equivalent URIs', async () => {
  const result = await fixture([
    { uri: legacy }, null, { space: { uri: other } }, { space: uri, repoRev: '3k' },
    other, { name: 'test' }, { uri: '' }, { uri: uri + '/did:plc:bob/com.example.post/3k' }, { uri, space: other },
  ])
  assert.deepEqual(result, { uris: [legacy, other], withRepo: new Set([legacy]), skipped: 5 })
})

test('follows cursors even through empty pages and pages with only skipped entries', async () => {
  const requests = []
  const result = await listSpaceRefs(async (cursor) => {
    requests.push(cursor)
    if (cursor === undefined) return { spaces: [null], cursor: 'empty' }
    if (cursor === 'empty') return { spaces: [], cursor: 'next' }
    return { spaces: [{ space: uri }] }
  }, 100)
  assert.deepEqual(requests, [undefined, 'empty', 'next'])
  assert.deepEqual(result, { uris: [uri], withRepo: new Set(), skipped: 1 })
})

test('keeps earlier references after a request failure, invalid page, or cursor loop', async () => {
  for (const next of [
    () => { throw new Error('network failed') },
    () => ({ spaces: null }),
    () => ({ spaces: [], cursor: 'next' }),
  ]) {
    const result = await listSpaceRefs(async (cursor) => cursor ? next() : { spaces: [uri], cursor: 'next' }, 100)
    assert.deepEqual(result.uris, [uri])
    assert.equal(result.skipped, 0)
    assert.match(result.listingError, /^Page 2:/)
  }
  assert.deepEqual(await fixture([]), { uris: [], withRepo: new Set(), skipped: 0 })
  assert.match((await fixture({})).listingError, /^Page 1:/)
})

test('a copy failure leaves other spaces eligible and retry preserves verified progress', async () => {
  const requests = []
  let saved = []
  const copy = async (p) => {
    requests.push(p.uri)
    if (requests.length === 1) throw new Error('import failed')
    return { uri: p.uri, state: 'moved', filesVerified: true }
  }
  const persist = (moves) => { saved = moves }
  await copyPendingSpaces([{ uri }, { uri: other }], saved, copy, persist, String)
  assert.deepEqual(saved.map((m) => m.state), ['failed', 'moved'])
  assert.match(saved[0].reason, /import failed/)
  await copyPendingSpaces([{ uri: legacy }, { uri: other }], saved, copy, persist, String)
  assert.deepEqual(requests, [uri, other, legacy])
  assert.deepEqual(saved, [{ uri: legacy, state: 'moved', filesVerified: true }, { uri: other, state: 'moved', filesVerified: true }])
})

test('automatic deactivation requires a complete Spaces check with no failed copies', () => {
  for (const saved of [
    {}, { spaces: 'none' }, { spaces: 'done' }, { spaces: 'skipped', spaceCheckComplete: true },
    { spaces: 'done', spaceCheckComplete: true, spaceListing: { skipped: 1 } },
    { spaces: 'none', spaceCheckComplete: true, spaceListing: { skipped: 0, listingError: 'Page 1 failed' } },
    { spaces: 'done', spaceCheckComplete: true, spaceMoves: [{ uri, state: 'failed' }] },
  ]) assert.equal(canDeactivateOld(saved), false)
  for (const spaces of ['none', 'done']) assert.equal(canDeactivateOld({ spaces, spaceCheckComplete: true }), true)
})

test('retries unverified receipts without losing their provenance on failure', async () => {
  const old = [{ uri, state: 'moved', records: 5, blobs: 0 }]
  assert.equal(canDeactivateOld({ spaces: 'done', spaceCheckComplete: true, spaceMoves: old }), false)
  let saved = receiptsForRetry(old)
  assert.equal(saved[0].recheckReceipt, true)
  await copyPendingSpaces([{ uri: legacy }], saved, async () => { throw new Error('list failed') }, (moves) => { saved = moves }, String)
  assert.equal(saved[0].recheckReceipt, true)
  assert.equal(saved[0].records, 5)
  assert.equal(saved[0].state, 'failed')
  assert.equal(canDeactivateOld({ spaces: 'done', spaceCheckComplete: true, spaceMoves: saved }), false)
})

test('old finishedAt values with unresolved Spaces remain resumable', () => {
  const saved = { activated: true, finishedAt: 1 }
  const skipped = { ...saved, spaces: 'skipped', spaceListing: { skipped: 1 } }
  assert.equal(isMigrationDone(skipped), false)
  assert.equal(isMigrationDone({ ...skipped, oldDeactivated: true }), false)
  assert.equal(isMigrationDone({ ...saved, spaces: 'done', spaceCheckComplete: true, spaceMoves: [{ uri, state: 'moved' }] }), false)
  assert.equal(isMigrationDone({ ...saved, oldDeactivated: true }), true)
  assert.equal(isMigrationDone({ ...saved, spaces: 'none', spaceCheckComplete: true, deactivationDeferred: true }), true)
})
