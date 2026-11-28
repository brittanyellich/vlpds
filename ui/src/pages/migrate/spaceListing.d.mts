import type { Saved } from './flow'

export function spaceKey(uri: unknown): string | undefined
export function nextCursor(cursor: unknown, seen: Set<string>): string | undefined
export type SpaceListing = { uris: string[]; withRepo: Set<string>; skipped: number; listingError?: string }
export function listSpaceRefs(readPage: (cursor?: string) => Promise<unknown>, maxEntries: number): Promise<SpaceListing>
export function canDeactivateOld(saved: Pick<Saved, 'spaces' | 'spaceCheckComplete' | 'spaceListing' | 'spaceMoves'>): boolean
export function copyPendingSpaces<T extends { uri: string }>(
  plans: T[],
  previous: import('./spaces').SpaceMove[],
  copy: (plan: T) => Promise<import('./spaces').SpaceMove>,
  onMove: (moves: import('./spaces').SpaceMove[]) => void,
  reasonOf: (error: unknown) => string,
): Promise<void>
