// Run against a local Vite server: node ui/scripts/test-space-migration.mjs [port]
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { chromium } from 'playwright'

const port = process.argv[2] ?? '5173'
const origin = `http://127.0.0.1:${port}`
const fixtureDir = new URL('../../testdata/spaces-alpha/', import.meta.url)
const fixture = JSON.parse(readFileSync(new URL('export.json', fixtureDir), 'utf8'))
const archive = [...readFileSync(new URL('export.star', fixtureDir))]
const blob = [...Buffer.from(fixture.blob.bytesHex, 'hex')]

const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE
const browser = await chromium.launch({ executablePath })
try {
  const context = await browser.newContext()
  let external = 0
  let deactivations = 0
  await context.route('**/*', (route) => {
    const url = new URL(route.request().url())
    if (url.origin !== origin) {
      external++
      return route.abort()
    }
    if (!url.pathname.startsWith('/xrpc/')) return route.continue()
    if (url.pathname.endsWith('.deactivateAccount')) deactivations++
    return route.fulfill({ json: { availableUserDomains: ['example.test'], inviteCodeRequired: false, vlpds: {} } })
  })
  const page = await context.newPage()
  await page.goto(origin)
  const result = await page.evaluate(async ({ fixture, archive, blob }) => {
    const { copySpace, planSpace, recheckSpace } = await import('/src/pages/migrate/spaces.ts')
    const { XrpcError } = await import('/src/lib/xrpc.ts')
    const pause = () => {}
    const calls = []
    let listAvailable = false
    let mismatchedRepo = false
    const old = {
      did: fixture.did,
      async call(name) {
        if (name.endsWith('.listBlobs')) {
          if (!listAvailable) throw new XrpcError(400, 'RepoNotFound', 'Synthetic file list unavailable')
          return { cids: [fixture.blob.cid] }
        }
        if (name.endsWith('.getRepo')) return new Response(new Uint8Array(archive))
        if (name.endsWith('.getBlob')) return new Response(new Uint8Array(blob))
        throw new Error(`Unexpected source call: ${name}`)
      },
    }
    const here = {
      did: fixture.did,
      async call(name) {
        calls.push(name)
        if (name.endsWith('.getRepo')) {
          if (mismatchedRepo) throw new XrpcError(400, 'RepoNotFound', 'Synthetic destination repo unavailable')
          return new Response(new Uint8Array(archive))
        }
        if (name.endsWith('.uploadBlob')) return { blob: { ref: { $link: fixture.blob.cid } } }
        throw new Error(`Unexpected destination call: ${name}`)
      },
    }
    const errorOf = async (operation) => {
      try { await operation() } catch (error) { return error.message }
      return null
    }
    const missingExpected = await errorOf(() => planSpace(old, fixture.space, pause, true))
    const ambiguous = await planSpace(old, fixture.space, pause, false)
    const missingUnexpected = await errorOf(() => copySpace(old, here, ambiguous, pause, pause))
    const beforeRetry = [...calls]
    listAvailable = true
    const complete = await planSpace(old, fixture.space, pause, true)
    mismatchedRepo = true
    const missingDestination = await errorOf(() => recheckSpace(old, here, complete, pause, pause))
    mismatchedRepo = false
    const verified = await recheckSpace(old, here, complete, pause, pause)
    return { missingExpected, missingUnexpected, beforeRetry, missingDestination, verified, calls }
  }, { fixture, archive, blob })
  assert.match(result.missingExpected, /file list is unavailable/)
  assert.match(result.missingUnexpected, /file list is unavailable/)
  assert.deepEqual(result.beforeRetry, [])
  assert.match(result.missingDestination, /repos differ/)
  assert.deepEqual(result.verified, { uri: fixture.space, state: 'moved', filesVerified: true, blobs: 1, records: 5 })
  assert.deepEqual(result.calls, ['com.atproto.space.getRepo', 'com.atproto.space.getRepo', 'com.atproto.repo.uploadBlob'])

  const seed = async ({ spaces, spaceCheckComplete, spaceListing, spaceMoves, finishedAt }) => {
    await page.evaluate(({ spaces, spaceCheckComplete, spaceListing, spaceMoves, finishedAt }) => {
      const did = 'did:plc:syntheticowner'
      const jwt = 'x.' + btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, scope: 'com.atproto.access' })) + '.x'
      localStorage.setItem('vlpds.migrate', JSON.stringify({
        did, oldPds: 'https://synthetic.invalid', oldHandle: 'owner.example.test', newHandle: 'owner.example.test',
        checkedAt: 1, created: true, repoDone: true, blobsDone: true, prefsDone: true, backup: 'saved',
        identityDone: true, activated: true, spaces, spaceCheckComplete, spaceListing, spaceMoves, startedAt: 1, finishedAt,
      }))
      const tokens = { accessJwt: jwt, refreshJwt: 'synthetic' }
      sessionStorage.setItem('vlpds.migrate.secrets', JSON.stringify({ did, old: tokens, new: tokens }))
    }, { spaces, spaceCheckComplete, spaceListing, spaceMoves, finishedAt })
    await page.goto(`${origin}/migrate`)
    await page.getByRole('button', { name: 'Check Spaces again' }).waitFor()
  }
  await seed({ spaces: 'skipped', spaceListing: { skipped: 1 }, finishedAt: 1 })
  await page.reload()
  await page.getByRole('button', { name: 'Check Spaces again' }).waitFor()
  assert.equal(await page.getByText('Welcome to your new home').count(), 0)
  assert.equal(await page.getByRole('button', { name: 'Finish with the old account active' }).count(), 0)
  await seed({ spaces: 'done', spaceCheckComplete: true, spaceMoves: [{ uri: fixture.space, state: 'moved', records: 5, blobs: 0 }] })
  assert.equal(await page.getByText('Welcome to your new home').count(), 0)
  assert.equal(deactivations, 0)
  assert.equal(external, 0)
  console.log('Synthetic browser passed: missing file lists, read-back retry, and resumable saved migrations. Zero external requests or deactivations.')
} finally {
  await browser.close()
}
