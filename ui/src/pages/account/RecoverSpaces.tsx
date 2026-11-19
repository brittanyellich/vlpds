import { useEffect, useState } from 'react'
import { ErrorNotice, Field, Notice, Panel, Spinner } from '../../components/ui'
import { useSession } from '../../lib/hooks'
import { ACCOUNT_CALLBACK_PATH, beginSignIn, forgetAll, OAuthSession } from '../../lib/oauth'
import { copySpace, newScope, OLD_SCOPE, plan, reasonOf, type SpacePlan } from '../migrate/spaces'
import { clearRecovery, loadRecovery, saveRecovery, sourceUrl, type SpaceRecovery } from '../migrate/spaceRecovery'

const OLD = 'recovery-old'
const NEW = 'recovery-new'
const RETURN = '/account/spaces'

/** Explicit post-migration copy. Never changes the DID or account activation. */
export function RecoverSpaces() {
  const { did } = useSession()!
  const [hint, setHint] = useState<SpaceRecovery | null>(() => loadRecovery(did))
  const [open, setOpen] = useState(false)
  const [host, setHost] = useState(hint?.oldPds ?? '')
  const [old, setOld] = useState<OAuthSession | null>(null)
  const [here, setHere] = useState<OAuthSession | null>(null)
  const [plans, setPlans] = useState<SpacePlan[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const [results, setResults] = useState<{ uri: string; error?: string }[]>([])
  const source = sourceUrl(host, location.origin)

  useEffect(() => {
    if (!open || !source) return
    let alive = true
    void Promise.all([OAuthSession.load(OLD, did, source), OAuthSession.load(NEW, did, location.origin)])
      .then(([a, b]) => { if (alive) { setOld(a); setHere(b) } })
      .catch((e) => { if (alive) setError(e) })
    return () => { alive = false }
  }, [open, source, did])

  const run = async (task: () => Promise<void>) => {
    setBusy(true)
    setError(undefined)
    try { await task() } catch (e) { setError(e) } finally { setBusy(false) }
  }
  const start = async (name: string, pds: string, scope: string) =>
    run(() => beginSignIn({ name, pds, did, scope, callback: ACCOUNT_CALLBACK_PATH, returnTo: RETURN }))

  const check = () => run(async () => {
    if (!old) return
    const found = await plan(old, () => undefined)
    setPlans(found)
    const known = hint?.oldPds === source ? hint.completed : []
    const next = { did, oldPds: source!, completed: known }
    saveRecovery(next)
    setHint(next)
  })

  const copy = () => run(async () => {
    if (!old || !here || !plans || !source) return
    const completed = new Set(hint?.oldPds === source ? hint.completed : [])
    const output: { uri: string; error?: string }[] = []
    for (const item of plans) {
      if (completed.has(item.uri)) continue
      try {
        const result = await copySpace(old, here, item, () => undefined, () => undefined)
        if (result.state === 'moved' || result.state === 'empty') {
          completed.add(item.uri)
          saveRecovery({ did, oldPds: source, completed: [...completed] })
        }
        output.push({ uri: item.uri })
      } catch (e) {
        output.push({ uri: item.uri, error: reasonOf(e) })
      }
      setResults([...output])
    }
    if (output.every((r) => !r.error) && plans.every((p) => completed.has(p.uri))) {
      clearRecovery(did)
      setHint(null)
      await forgetAll([OLD, NEW])
      setOld(null)
      setHere(null)
    }
  })

  return (
    <Panel title={hint ? 'Uncopied Spaces from your previous server' : 'Spaces on a previous server?'}>
      <p>{hint
        ? `A previous move left Spaces at ${new URL(hint.oldPds).host}. They are not shown in the lists below until copied.`
        : 'If you skipped the Spaces step during a move, you can try copying them separately. Older moves may not be detected automatically.'}</p>
      {!open ? (
        <button type="button" className="btn" onClick={() => setOpen(true)}>Check previous server</button>
      ) : (
        <>
          <Field label="Previous PDS address" hint="Use the server address, not your handle or DID.">
            <input type="url" value={host} onChange={(e) => { setHost(e.target.value); setOld(null); setPlans(null) }} placeholder="https://your-old-pds.example" />
          </Field>
          {!source && <Notice kind="warn">Enter the HTTPS address of your previous PDS (not this one).</Notice>}
          <Notice kind="info">This only reads from your previous server and imports Spaces here. It does not move your DID or activate or deactivate either account. Your old server may refuse a new sign-in while the old account is deactivated; if it does, stop here and contact its operator. Do not reset your migration.</Notice>
          <ErrorNotice error={error} />
          {source && !old && <button type="button" className="btn" disabled={busy} onClick={() => start(OLD, source, OLD_SCOPE)}>Authorize read at previous PDS</button>}
          {old && !old.grants(OLD_SCOPE) && <Notice kind="warn">The previous-server sign-in did not grant read access to your Spaces. Reauthorize with the requested permission.</Notice>}
          {old && !old.grants(OLD_SCOPE) && <button type="button" className="btn" disabled={busy} onClick={() => start(OLD, source!, OLD_SCOPE)}>Reauthorize source</button>}
          {old?.grants(OLD_SCOPE) && !plans && <button type="button" className="btn" disabled={busy} onClick={check}>Check source Spaces</button>}
          {plans && <p>{plans.length} {plans.length === 1 ? 'Space' : 'Spaces'} found; {plans.filter((p) => hint?.oldPds === source && hint.completed.includes(p.uri)).length} previously copied in this browser.</p>}
          {plans && plans.length > 0 && !here && <button type="button" className="btn" disabled={busy} onClick={() => start(NEW, location.origin, newScope(plans))}>Authorize import here</button>}
          {plans && plans.length > 0 && here && !here.grants(newScope(plans)) && <Notice kind="warn">The destination sign-in did not grant the permissions required for these Spaces. Reauthorize with all requested permissions.</Notice>}
          {plans && plans.length > 0 && here && !here.grants(newScope(plans)) && <button type="button" className="btn" disabled={busy} onClick={() => start(NEW, location.origin, newScope(plans))}>Reauthorize import</button>}
          {plans && plans.length > 0 && here?.grants(newScope(plans)) && <button type="button" className="btn primary" disabled={busy} onClick={copy}>{busy && <Spinner />} Copy remaining Spaces</button>}
          {results.map((r) => <p key={r.uri}>{r.uri}: {r.error ? `Not copied — ${r.error}` : 'Copied'}</p>)}
          {plans?.length === 0 && <Notice kind="info">The previous server listed no Spaces for this account. Nothing was imported.</Notice>}
        </>
      )}
    </Panel>
  )
}
