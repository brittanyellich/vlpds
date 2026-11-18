/** Non-secret, browser-local hint for an unfinished Spaces copy. This is not
 * proof of server state: the account page always checks the source afresh. */
export type SpaceRecovery = { did: string; oldPds: string; completed: string[] }

const key = (did: string) => `vlpds.spaces.recovery.${did}`

export function sourceUrl(value: string, destination: string): string | null {
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || url.origin === destination) return null
    return url.origin
  } catch {
    return null
  }
}

export function loadRecovery(did: string): SpaceRecovery | null {
  try {
    const value = JSON.parse(localStorage.getItem(key(did)) ?? 'null')
    const oldPds = typeof value?.oldPds === 'string' ? sourceUrl(value.oldPds, location.origin) : null
    return value?.did === did && oldPds
      ? { did, oldPds, completed: Array.isArray(value.completed) ? value.completed.filter((s: unknown) => typeof s === 'string') : [] }
      : null
  } catch {
    return null
  }
}

export function saveRecovery(value: SpaceRecovery) {
  try {
    localStorage.setItem(key(value.did), JSON.stringify(value))
  } catch {
    /* Storage disabled: the current session can still work. */
  }
}

export function clearRecovery(did: string) {
  try {
    localStorage.removeItem(key(did))
  } catch {
    /* Storage disabled. */
  }
}
