import { useEffect, useState, type FormEvent } from 'react'
import { CopyText, Field, Notice, Panel } from '../../components/ui'
import { call, getSession, XrpcError, type CallOpts } from '../../lib/xrpc'

type Operation = { operationId: string; handle: string }
type Provisioning = Operation & { status: 'reserved' | 'pending' | 'needsReconciliation' | 'ready'; did?: string }

function loadOperation(key: string): Operation | null {
  try {
    const saved = JSON.parse(sessionStorage.getItem(key) ?? 'null')
    return typeof saved?.operationId === 'string' && typeof saved.handle === 'string'
      ? { operationId: saved.operationId, handle: saved.handle }
      : null
  } catch {
    return null
  }
}

function ownerCall<T>(owner: string, method: string, options: CallOpts): Promise<T> {
  const session = getSession()
  if (session?.did !== owner) throw new Error('The signed-in owner changed')
  return call<T>(method, { ...options, auth: `Bearer ${session.accessJwt}` })
}

export function CreateAgent({ owner }: { owner: string }) {
  const key = `vlpds.agent.provision.${owner}`
  const [operation, setOperation] = useState(() => loadOperation(key))
  const [result, setResult] = useState<Provisioning>()
  const [busy, setBusy] = useState(!!operation)
  const [missing, setMissing] = useState(false)
  const [error, setError] = useState('')

  async function check(saved: Operation, signal?: AbortSignal) {
    setBusy(true)
    setMissing(false)
    setError('')
    try {
      const current = await ownerCall<Provisioning>(owner, 'vlpds.agent.getProvisioningStatus', {
        params: { operationId: saved.operationId }, signal,
      })
      if (signal?.aborted) return
      setResult(current)
      return current
    } catch (cause) {
      if (signal?.aborted) return
      setResult(undefined)
      if (cause instanceof XrpcError && cause.error === 'AgentReservationNotFound') setMissing(true)
      else setError('Could not check provisioning status. Try checking again.')
    } finally {
      if (!signal?.aborted) setBusy(false)
    }
  }

  useEffect(() => {
    const saved = loadOperation(key)
    if (!saved) return
    const controller = new AbortController()
    void check(saved, controller.signal)
    return () => controller.abort()
  }, [key])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || (operation && result?.status !== 'reserved' && !missing)) return
    const form = event.currentTarget
    const fields = new FormData(form)
    const handle = String(fields.get('handle') ?? '').trim()
    const saved = operation && (!missing || operation.handle === handle)
      ? operation
      : { operationId: crypto.randomUUID(), handle }
    try {
      sessionStorage.setItem(key, JSON.stringify(saved))
    } catch {
      setError('Enable session storage so this operation can be recovered after reload.')
      form.reset()
      return
    }
    setOperation(saved)
    setResult(undefined)
    setMissing(false)
    setError('')
    setBusy(true)

    const inviteCode = String(fields.get('inviteCode') ?? '').trim()
    const body = { ...saved, email: String(fields.get('email') ?? '').trim(), password: String(fields.get('password') ?? ''), ...(inviteCode && { inviteCode }) }
    form.reset()
    try {
      setResult(await ownerCall<Provisioning>(owner, 'vlpds.agent.provision', { body }))
    } catch (cause) {
      const current = await check(saved)
      if (current?.status === 'ready') return
      setError(cause instanceof XrpcError && cause.status < 500
        ? `Signup was refused (${cause.error}). Check the signup details and operation status.`
        : 'Signup response was interrupted. Check this operation before retrying.')
    } finally {
      setBusy(false)
    }
  }

  const canSubmit = !operation || missing || result?.status === 'reserved'
  return (
    <Panel title="Create agent" desc="Create a separate account for your agent using this server's signup policy.">
      {error && <Notice kind="err">{error}</Notice>}
      {operation && (
        <p role="status">
          {busy ? 'Checking agent provisioning…'
            : result?.status === 'ready' ? 'Agent account ready.'
            : result?.status === 'needsReconciliation' ? 'Signup needs reconciliation. Check status before taking further action.'
            : result?.status === 'pending' ? 'Signup is pending. Check status to resume.'
            : result?.status === 'reserved' ? 'The operation is reserved. You can retry signup.'
            : missing ? 'No reservation was found. You can submit signup again.'
            : 'The saved operation is awaiting a status check.'}
        </p>
      )}
      {result?.status === 'ready' && result.did && (
        <p>Agent DID <CopyText text={result.did} /> Sign in as the agent to complete its declaration, and approve the matching owner endorsement.</p>
      )}
      {operation && result?.status !== 'ready' && (
        <button type="button" className="btn" disabled={busy} onClick={() => void check(operation)}>Check status</button>
      )}
      {canSubmit && (
        <form onSubmit={submit} autoComplete="off">
          <Field label="Agent handle">
            <input name="handle" required defaultValue={operation?.handle} readOnly={result?.status === 'reserved'} />
          </Field>
          <Field label="Agent email">
            <input name="email" type="email" required />
          </Field>
          <Field label="Agent password">
            <input name="password" type="password" autoComplete="new-password" required />
          </Field>
          <Field label="Invite code (if required)">
            <input name="inviteCode" />
          </Field>
          <button type="submit" className="btn primary" disabled={busy}>{operation ? 'Retry signup' : 'Create agent'}</button>
        </form>
      )}
    </Panel>
  )
}
