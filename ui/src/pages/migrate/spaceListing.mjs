// Keep the wire URI for source requests and normalize only for identity checks.
export function spaceKey(uri) {
  if (typeof uri !== 'string') return undefined
  const match = /^at:(?:space\/(did:[a-z]+:[a-zA-Z0-9:._%-]+)|\/\/(did:[a-z]+:[a-zA-Z0-9:._%-]+)\/space)\/([a-zA-Z0-9.-]+)\/([a-zA-Z0-9._~:-]+)$/.exec(uri)
  if (!match || match[0] !== uri) return undefined
  const authority = match[1] ?? match[2]
  const [, , , type, skey] = match
  if (authority.length > 2048 || /[:%]$/.test(authority) || skey.length > 512 || skey === '.' || skey === '..') return undefined
  const labels = type.split('.')
  if (type.length > 317 || labels.length < 3 || !/^[a-zA-Z]/.test(type) || !/^[a-zA-Z][a-zA-Z0-9]*$/.test(labels.at(-1))) return undefined
  if (labels.some((label) => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return undefined
  return `at:space/${authority}/${type}/${skey}`
}

export function nextCursor(cursor, seen) {
  if (cursor === undefined) return undefined
  if (typeof cursor !== 'string' || !cursor.trim() || seen.has(cursor)) throw new Error('The server returned an invalid or repeated cursor.')
  seen.add(cursor)
  return cursor
}

export async function listSpaceRefs(readPage, maxEntries) {
  const refs = new Map()
  const withRepo = new Set()
  const seen = new Set()
  let skipped = 0
  let count = 0
  let page = 0
  try {
    for (let cursor; ; ) {
      page++
      const response = await readPage(cursor)
      if (!Array.isArray(response?.spaces)) throw new Error('Expected a Spaces list.')
      for (const entry of response.spaces) {
        if (++count > maxEntries) throw new Error(`The listing exceeded ${maxEntries} entries.`)
        const candidates = [entry?.space, entry?.space?.uri, entry?.uri, entry]
        const valid = candidates.map((uri) => ({ uri, key: spaceKey(uri) })).filter(({ key }) => key)
        const first = valid[0]
        if (first && valid.every(({ key }) => key === first.key)) {
          const { uri, key } = first
          if (!refs.has(key)) refs.set(key, uri)
          if (entry?.repoRev || entry?.data) withRepo.add(refs.get(key))
        } else {
          skipped++
        }
      }
      cursor = nextCursor(response.cursor, seen)
      if (cursor === undefined) return { uris: [...refs.values()], withRepo, skipped }
      if (page >= maxEntries) throw new Error(`The listing exceeded ${maxEntries} pages.`)
    }
  } catch (error) {
    return { uris: [...refs.values()], withRepo, skipped, listingError: `Page ${page}: ${error instanceof Error ? error.message : String(error)}` }
  }
}

export const isVerifiedMove = (move) => move.filesVerified === true && (move.state === 'moved' || move.state === 'empty')

const hasListingGaps = (listing) => !!(listing?.skipped || listing?.listingError)

export function canDeactivateOld({ spaces, spaceCheckComplete, spaceListing, spaceMoves }) {
  return spaceCheckComplete === true && (spaces === 'none' || spaces === 'done') &&
    !hasListingGaps(spaceListing) && !spaceMoves?.some((move) => !isVerifiedMove(move))
}

export function isMigrationDone(saved) {
  if (!saved.activated) return false
  if (saved.oldDeactivated) {
    // Historical completed migrations are still done. Explicit unresolved
    // outcomes must stay accessible even if an older build switched off the source.
    return saved.spaces !== 'skipped' && !hasListingGaps(saved.spaceListing) &&
      !saved.spaceMoves?.some((move) => move.state === 'failed' || (saved.spaceCheckComplete && !isVerifiedMove(move)))
  }
  return saved.deactivationDeferred === true && canDeactivateOld(saved)
}

export function receiptsForRetry(moves) {
  return moves.map((move) => {
    if (isVerifiedMove(move) || move.state === 'failed') return move
    return {
      ...move,
      state: 'failed',
      recheckReceipt: true,
      reason: 'The earlier copy still needs its files checked.',
    }
  })
}

export async function copyPendingSpaces(plans, previous, copy, onMove, reasonOf) {
  const moves = new Map(previous.map((move) => [spaceKey(move.uri), move]))
  for (const plan of plans) {
    const key = spaceKey(plan.uri)
    const prior = moves.get(key)
    if (prior && isVerifiedMove(prior)) continue
    let move
    try {
      move = await copy(plan)
    } catch (error) {
      move = { ...prior, uri: plan.uri, state: 'failed', reason: reasonOf(error) }
    }
    moves.set(key, move)
    onMove([...moves.values()])
  }
}
