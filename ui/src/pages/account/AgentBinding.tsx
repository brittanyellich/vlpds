import { useState } from 'react'
import { ErrorNotice, Field, Loading, Notice, Panel, Spinner } from '../../components/ui'
import { useAction, useLoad } from '../../lib/hooks'
import { acall, XrpcError } from '../../lib/xrpc'

type PlcData = {
  did: string
  alsoKnownAs: string[]
  verificationMethods: Record<string, string>
  rotationKeys: string[]
  services: Record<string, unknown>
}

const prefix = 'https://ident.link/agent-of/'
const plcDid = /^did:plc:[a-z2-7]{24}$/
function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`
  if (value && typeof value === 'object')
    return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(',')}}`
  return JSON.stringify(value) ?? 'undefined'
}
const same = (a: unknown, b: unknown) => stable(a) === stable(b)

/** Only the alias list may change; check the signed operation before submitting it. */
function checkOperation(operation: any, before: PlcData, aliases: string[]) {
  if (!operation || !same(operation.alsoKnownAs, aliases) ||
      !same(operation.verificationMethods, before.verificationMethods) ||
      !same(operation.rotationKeys, before.rotationKeys) ||
      !same(operation.services, before.services)) {
    throw new Error('The signed PLC operation changed more than the proposed alias. Nothing was submitted.')
  }
}

export function AgentBinding({ did, handle }: { did: string; handle: string }) {
  const data = useLoad<PlcData>(() => acall('vlpds.identity.getPlcData'), [did])
  const [principal, setPrincipal] = useState('')
  const [pending, setPending] = useState<string>()
  const [code, setCode] = useState('')
  const [done, setDone] = useState(false)
  const aliases = data.data?.alsoKnownAs.filter((alias) => alias.startsWith(prefix)) ?? []
  const valid = plcDid.test(principal.trim()) && principal.trim() !== did
  const alias = `${prefix}${principal.trim()}`
  const start = useAction(async () => {
    const current = await acall<PlcData>('vlpds.identity.getPlcData')
    if (current.did !== did || current.alsoKnownAs?.[0] !== `at://${handle}` || current.alsoKnownAs.includes(alias))
      throw new Error('The account identity changed or this declaration already exists. Reload and review it again.')
    await acall('com.atproto.identity.requestPlcOperationSignature', { method: 'POST' })
    setPending(alias)
    setCode('')
    setDone(false)
  })
  const apply = useAction(async () => {
    if (!pending) return
    const before = await acall<PlcData>('vlpds.identity.getPlcData')
    if (before.did !== did || before.alsoKnownAs?.[0] !== `at://${handle}` || before.alsoKnownAs.includes(pending))
      throw new Error('The account identity changed. Cancel and review it again.')
    const next = [...before.alsoKnownAs, pending]
    const { operation } = await acall<{ operation: unknown }>('com.atproto.identity.signPlcOperation', {
      body: { token: code.trim(), alsoKnownAs: next },
    })
    checkOperation(operation, before, next)
    await acall('com.atproto.identity.submitPlcOperation', { body: { operation } })
    setPending(undefined)
    setCode('')
    setPrincipal('')
    setDone(true)
    data.reload()
  })
  const off = data.error instanceof XrpcError && (data.error.status === 501 || data.error.error === 'InvalidRequest')
  return (
    <Panel title="Agent identity declaration" id="agent-binding" desc="Publicly declare that this account is an agent of a human DID. This does not grant access or publish the human's endorsement.">
      {off ? <Notice>This account cannot edit its PLC identity here.</Notice> : <ErrorNotice error={data.error} />}
      {!data.data && !data.error && <Loading />}
      {data.data && (
        <>
          <p>Agent DID: <span className="mono">{did}</span></p>
          {aliases.length > 0 && <ul>{aliases.map((item) => <li className="mono" key={item}>{item}</li>)}</ul>}
          {done && <Notice kind="ok">Declaration submitted. The human must separately endorse this agent from their own account.</Notice>}
      <ErrorNotice error={start.error || apply.error} />
          {pending ? (
            <form onSubmit={(e) => { e.preventDefault(); apply.run() }}>
              <Notice>This will publicly add <span className="mono">{pending}</span> to your DID document. No existing aliases, keys, or services will be removed. Enter the code emailed to this account to sign and submit. If submission fails after signing, cancel and request a new code.</Notice>
              <Field label="PLC confirmation code">
                <input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" spellCheck={false} required autoFocus />
              </Field>
              <div className="row">
                <button type="button" className="btn" onClick={() => { setPending(undefined); setCode('') }}>Cancel</button>
                <button className="btn primary" disabled={apply.busy || !code.trim()}>{apply.busy && <Spinner />}Sign and publish declaration</button>
              </div>
            </form>
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); if (valid && !aliases.includes(alias)) start.run() }}>
              <Field label="Human principal DID" hint="Enter the exact did:plc of the person this agent belongs to.">
                <input value={principal} onChange={(e) => setPrincipal(e.target.value)} placeholder="did:plc:…" spellCheck={false} required />
              </Field>
              <button className="btn" disabled={!valid || aliases.includes(alias) || start.busy}>{start.busy && <Spinner />}Email confirmation code</button>
            </form>
          )}
        </>
      )}
    </Panel>
  )
}
