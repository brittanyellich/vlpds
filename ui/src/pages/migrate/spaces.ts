// The migration's Spaces step: the spaces the account runs and the space
// repos it writes, copied from the old PDS to this one once the account is
// live here. Space data is OAuth-only on both sides, so each side gets its
// own OAuth sign-in with only what its half needs: reading the account's own
// spaces there, importing them (and, when they name any, uploading blobs)
// here. A space the account runs moves first (exportSpaceMeta there,
// importSpaceMeta here), since its owner's repo can't be imported before it.

import type { OAuthSession } from '../../lib/oauth'
import { XrpcError } from '../../lib/xrpc'
import { retry } from '../../lib/backoff'
import { decode } from 'cborg'
import { spaceUriParts } from '../../lib/spaceUri'
import { listSpaceRefs, nextCursor, spaceKey, type SpaceListing } from './spaceListing.mjs'

export const OLD_SCOPE = 'atproto space:*?authority=*&action=read_self'
export const NEW_SCOPE = 'atproto space:*?authority=*&collection=*'
export const BLOB_SCOPE = 'blob:*/*'
/** Importing the spaces the account runs (`authority` defaults to the account itself). */
export const GOVERN_SCOPE = 'space:*?manage=create&manage=update'

/** What the sign-in here needs for `plans`. */
export const newScope = (plans: SpacePlan[]) =>
  [NEW_SCOPE, plans.some((p) => p.governed) && GOVERN_SCOPE, plans.some((p) => p.blobs.length) && BLOB_SCOPE].filter(Boolean).join(' ')

/** Saved per space (no secrets), so a reload shows the outcome and retries only what didn't move. */
export type SpaceMove = {
  uri: string
  state: 'moved' | 'failed' | 'empty'
  records?: number
  blobs?: number
  reason?: string
}

/** Past these, a listing that keeps paging is broken (or hostile), not big:
 * a repo holds at most 100k records. */
const MAX_SPACES = 10_000
const MAX_BLOBS = 100_000

/** `governed`: the account is the space's authority, so the space itself moves too. */
export type SpacePlan = { uri: string; blobs: string[]; governed: boolean; expectsRepo: boolean }

/** Whether `base` serves Spaces at all: an unauthenticated listSpaces is
 * refused for want of auth there, and as an unknown method elsewhere. */
export async function servesSpaces(base: string): Promise<boolean> {
  let r: Response
  try {
    r = await fetch(`${base}/xrpc/com.atproto.space.listSpaces`)
  } catch {
    throw new Error(`Couldn't reach ${new URL(base, location.href).host}. Check your connection and retry.`)
  }
  if (r.status === 401) return true
  const body = await r.json().catch(() => ({}))
  if (r.status === 400 && /^Auth/.test(body.error ?? '')) return true
  if ((r.status === 404 || r.status === 501 || r.status === 400) &&
      ['XRPCNotSupported', 'MethodNotImplemented', 'UnknownMethod', 'MethodNotFound'].includes(body.error)) return false
  // An ambiguous probe is followed up with the authenticated listing.
  return true
}

const repoNotFound = (e: unknown) => e instanceof XrpcError && e.error === 'RepoNotFound'

/** Keep usable references from every page, including pages before a listing error. */
export function list(old: OAuthSession, onPause: (until: number) => void): Promise<SpaceListing> {
  return listSpaceRefs(
    (cursor) => retry(() => old.call('com.atproto.space.listSpaces', { params: { limit: 100, cursor } }), onPause),
    MAX_SPACES,
  )
}

export async function planSpace(old: OAuthSession, uri: string, onPause: (until: number) => void, expectsRepo: boolean): Promise<SpacePlan> {
  const blobs = new Set<string>()
  const seen = new Set<string>()
  try {
    for (let cursor: string | undefined; ; ) {
      const page = await retry(() => old.call('com.atproto.space.listBlobs', { params: { space: uri, repo: old.did, limit: 1000, cursor } }), onPause)
      if (!Array.isArray(page?.cids) || page.cids.some((cid: unknown) => typeof cid !== 'string' || !cid))
        throw new Error('The old server returned an invalid file list.')
      for (const cid of page.cids) blobs.add(cid)
      if (blobs.size > MAX_BLOBS || seen.size >= MAX_BLOBS) throw new Error(`The file listing exceeded ${MAX_BLOBS} files or pages.`)
      cursor = nextCursor(page.cursor, seen)
      if (cursor === undefined) break
    }
  } catch (e) {
    if (!repoNotFound(e) || blobs.size || seen.size) throw e
  }
  return { uri, blobs: [...blobs], expectsRepo, governed: spaceLabel(uri).authority === old.did }
}

/** Account recovery requires a complete listing before clearing its recovery hint. */
export async function plan(old: OAuthSession, onPause: (until: number) => void): Promise<SpacePlan[]> {
  const listing = await list(old, onPause)
  if (listing.listingError) throw new Error(listing.listingError)
  if (listing.skipped) throw new Error(`The previous server listed ${listing.skipped} Spaces without usable URIs.`)
  const plans: SpacePlan[] = []
  for (const uri of listing.uris) plans.push(await planSpace(old, uri, onPause, listing.withRepo.has(uri)))
  return plans
}

/** Plain words for the reasons an import is refused. */
export function reasonOf(e: unknown): string {
  if (e instanceof XrpcError) {
    const known: Record<string, string> = {
      InvalidRepoFile: 'the copy is damaged',
      InvalidSpaceMeta: "the copy of the space's settings is damaged",
      RepoMismatch: "the copy is another account's",
      UnsupportedPolicy: "this server doesn't support the space's access rules",
      NotAuthorized: "the space isn't yours to bring",
      SpaceNotFound: 'the space no longer exists',
      SpaceDeleted: 'the space was deleted',
      FutureRev: "its last change is dated in the future; check your device's clock and the old server's",
      RepoTooLarge: 'it is larger than this server takes',
      ScopeMissing: "the sign-in here didn't grant what the copy needs; sign in again and allow everything asked",
    }
    return known[e.error] ?? (e.message || e.error)
  }
  return e instanceof Error ? e.message : String(e)
}

/** For a space the account runs, its meta first (exportSpaceMeta there,
 * importSpaceMeta here); then the old server's getRepo, importRepo here, and
 * any blobs its records name. Both imports replace what's here, so a retry
 * is safe. */
export async function copySpace(
  old: OAuthSession,
  here: OAuthSession,
  p: SpacePlan,
  onPause: (until: number) => void,
  onBlob: (done: number) => void,
): Promise<SpaceMove> {
  if (p.governed) {
    const meta = await retry(() => old.call<Response>('com.atproto.space.exportSpaceMeta', { params: { space: p.uri }, raw: true }).then((r) => r.blob()), onPause)
    await verifyArchive(meta, p.uri)
    await retry(() => here.call('com.atproto.space.importSpaceMeta', { body: meta, type: 'application/vnd.dasl.star' }), onPause)
  }
  let star: Blob
  try {
    star = await retry(
      () => old.call<Response>('com.atproto.space.getRepo', { params: { space: p.uri, repo: old.did }, raw: true }).then((r) => r.blob()),
      onPause,
    )
  } catch (e) {
    if (repoNotFound(e) && !p.expectsRepo && !p.blobs.length) return p.governed ? { uri: p.uri, state: 'moved', records: 0, blobs: 0 } : { uri: p.uri, state: 'empty' }
    throw e
  }
  await verifyArchive(star, p.uri, old.did)
  const records = starPairs(new Uint8Array(await star.arrayBuffer()))
  // The destination validates and commits the archive before acknowledging the import.
  await retry(() => here.call('com.atproto.space.importRepo', { body: star, type: 'application/vnd.dasl.star' }), onPause)
  let n = 0
  for (const cid of p.blobs) {
    await retry(async () => {
      const r = await old.call<Response>('com.atproto.space.getBlob', { params: { space: p.uri, repo: old.did, cid }, raw: true })
      const type = r.headers.get('content-type') || 'application/octet-stream'
      const up = await here.call('com.atproto.repo.uploadBlob', { body: await r.blob(), type })
      const got = up?.blob?.ref?.$link
      if (got !== cid) throw new Error(`a file hashed to ${got ?? 'nothing'}, not ${cid}`)
    }, onPause)
    onBlob(++n)
  }
  return { uri: p.uri, state: 'moved', records, blobs: n }
}

/** Check the archive's identity before letting the destination replace data. */
async function verifyArchive(blob: Blob, uri: string, did?: string) {
  const header = new Uint8Array(await blob.slice(0, 12).arrayBuffer())
  if (header[0] !== 0x2a || header[1] !== 0x6c || header[2] !== 1 || header[3] !== 0)
    throw new Error('The old server returned an invalid Space archive.')
  let length = 0
  for (let i = 4; i < header.length; i++) {
    length += (header[i] & 0x7f) * 2 ** (7 * (i - 4))
    if (header[i] & 0x80) continue
    if (length > 64 * 1024 || i + 1 + length > blob.size) break
    const meta = decode(new Uint8Array(await blob.slice(i + 1, i + 1 + length).arrayBuffer()))
    if (spaceKey(meta?.space) !== spaceKey(uri) || (did && meta?.repo !== did))
      throw new Error('The Space archive belongs to a different Space or account.')
    return
  }
  throw new Error('The old server returned invalid Space archive metadata.')
}

/** The records in a getRepo archive (STAR: magic, metadata, then a 0x01
 * byte before each key/value pair and 0x00 at the end); undefined if it
 * doesn't parse, since the count is only shown. */
export function starPairs(b: Uint8Array): number | undefined {
  let i = 4
  const varint = () => {
    let v = 0
    for (let shift = 0; i < b.length; shift += 7) {
      const x = b[i++]
      v += (x & 0x7f) * 2 ** shift
      if (!(x & 0x80)) return v
    }
    return -1
  }
  const skip = () => {
    const n = varint()
    if (n < 0 || i + n > b.length) return false
    i += n
    return true
  }
  if (!skip()) return undefined
  for (let n = 0; i < b.length; n++) {
    if (b[i] === 0x00) return n
    if (b[i++] !== 0x01 || !skip() || !skip()) return undefined
  }
  return undefined
}

/** Space label from a current URI or a stored pre-Nov24 reference. */
export function spaceLabel(uri: string): { type: string; skey: string; authority: string } {
  const p = spaceUriParts(uri)
  return { type: p?.type ?? '', skey: p?.skey ?? '', authority: p?.authority ?? '' }
}
