// Older Spaces alpha servers may return a space ref in `space` rather than
// the current lexicon's `uri`. Never turn an unknown entry into an omitted
// `space` query parameter or conclude that there was nothing to copy.
export function spaceRefs(page) {
  if (!Array.isArray(page?.spaces)) throw new Error('The old server returned an invalid Spaces listing; nothing has been marked copied.')
  return page.spaces.map((entry) => {
    const uri = typeof entry === 'string' ? entry : entry?.uri ?? entry?.space?.uri ?? entry?.space
    if (typeof uri !== 'string' || !/^at:\/\/did:[a-z0-9:]+\/space\/[a-zA-Z0-9.-]+\/[^/?#]+$/.test(uri))
      throw new Error('The old server returned a Space without a usable URI; nothing has been marked copied.')
    return uri
  })
}
