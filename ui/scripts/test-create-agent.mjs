import assert from 'node:assert/strict'
import { chromium } from 'playwright'
import { createServer } from 'vite'

process.env.VLPDS_MOCK = '1'
const server = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await server.listen()
const address = server.httpServer.address()
const origin = `http://127.0.0.1:${address.port}`
let browser
try {
  browser = await chromium.launch()
  const page = await browser.newPage()
  const owner = (name) => ({ did: `did:plc:${name}`, handle: `${name}.example.com`, accessJwt: name, refreshJwt: name })
  const alice = owner('alice')
  const bob = owner('bob')
  const agentDid = 'did:plc:disposableagent'
  let operation
  let status = 'pending'
  let posts = 0
  const requested = []
  await page.addInitScript((session) => {
    if (!sessionStorage.getItem('vlpds.session')) sessionStorage.setItem('vlpds.session', JSON.stringify(session))
  }, alice)
  await page.route('**/xrpc/com.atproto.server.getSession', (route) => {
    const account = route.request().headers().authorization === 'Bearer alice' ? alice : bob
    return route.fulfill({ json: { did: account.did, handle: account.handle, active: true } })
  })
  await page.route('**/xrpc/vlpds.agent.provision', (route) => {
    posts++
    const { operationId, handle, ...signup } = route.request().postDataJSON()
    assert.equal(route.request().headers().authorization, 'Bearer alice')
    assert.deepEqual(signup, {
      email: 'disposable@example.com',
      password: 'synthetic agent password',
      inviteCode: 'synthetic-invite',
    })
    operation = { operationId, handle }
    // The reservation exists, but the caller never sees its POST response.
    return route.abort('connectionreset')
  })
  await page.route('**/xrpc/vlpds.agent.getProvisioningStatus?**', (route) => {
    requested.push(new URL(route.request().url()).searchParams.get('operationId'))
    assert.equal(route.request().headers().authorization, 'Bearer alice')
    return route.fulfill({ json: { ...operation, status, ...(status === 'ready' && { did: agentDid }) } })
  })

  await page.goto(origin + '/account')
  await page.getByLabel('Agent handle').fill('agent.example.com')
  await page.getByLabel('Agent email').fill('disposable@example.com')
  await page.getByLabel('Agent password').fill('synthetic agent password')
  await page.getByLabel('Invite code (if required)').fill('synthetic-invite')
  await page.getByRole('button', { name: 'Create agent', exact: true }).click()
  await page.getByText('Signup is pending. Check status to resume.').waitFor()
  const persisted = await page.evaluate(() => ({
    session: JSON.stringify(sessionStorage),
    local: JSON.stringify(localStorage),
    operation: JSON.parse(sessionStorage.getItem('vlpds.agent.provision.did:plc:alice')),
  }))
  assert.deepEqual(persisted.operation, operation)
  for (const value of ['disposable@example.com', 'synthetic agent password', 'synthetic-invite']) {
    assert.ok(!persisted.session.includes(value) && !persisted.local.includes(value))
  }
  assert.equal(await page.getByRole('button', { name: 'Retry signup' }).count(), 0)

  status = 'needsReconciliation'
  await page.getByRole('button', { name: 'Check status' }).click()
  await page.getByText('Signup needs reconciliation.', { exact: false }).waitFor()
  assert.equal(await page.getByRole('button', { name: 'Retry signup' }).count(), 0)
  status = 'ready'
  await page.reload()
  await page.getByText('Agent account ready.').waitFor()
  await page.getByText(agentDid, { exact: true }).waitFor()
  assert.equal(posts, 1)
  assert.ok(requested.length >= 3)
  assert.ok(requested.every((id) => id === operation.operationId))
  const aliceChecks = requested.length

  await page.evaluate((session) => sessionStorage.setItem('vlpds.session', JSON.stringify(session)), bob)
  await page.reload()
  await page.getByRole('button', { name: 'Create agent', exact: true }).waitFor()
  assert.equal(await page.getByText(agentDid, { exact: true }).count(), 0)
  assert.equal(requested.length, aliceChecks)
  console.log('Create agent preserves the operation across reload without signup secrets or cross-owner leakage.')
} finally {
  await browser?.close()
  await server.close()
}
