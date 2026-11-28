import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spaceRefs } from '../src/pages/migrate/spaceListing.mjs'

const uri = 'at:space/did:plc:exquicw7jew5vxerpgvc3x6w/com.example.group/main'
test('reads current and alpha Spaces listing shapes', () => {
  assert.deepEqual(spaceRefs({ spaces: [{ uri }, { space: uri }, { space: { uri } }, uri] }), [uri, uri, uri, uri])
})
test('preserves legacy refs when calling a host not yet upgraded', () => {
  const old = uri.replace(/^at:space\/([^/]+)\//, 'at://$1/space/')
  assert.deepEqual(spaceRefs({ spaces: [{ uri: old }] }), [old])
})
test('does not call listBlobs without a usable space ref', () => {
  for (const page of [{ spaces: [{ name: 'test' }] }, { spaces: [null] }, { spaces: [{ uri: '' }] }, { spaces: {} }])
    assert.throws(() => spaceRefs(page), /old server returned/)
})
