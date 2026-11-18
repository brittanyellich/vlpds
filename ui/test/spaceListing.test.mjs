import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spaceRefs } from '../src/pages/migrate/spaceListing.mjs'

const uri = 'at://did:plc:exquicw7jew5vxerpgvc3x6w/space/com.example.group/main'
test('reads current and alpha Spaces listing shapes', () => {
  assert.deepEqual(spaceRefs({ spaces: [{ uri }, { space: uri }, { space: { uri } }, uri] }), [uri, uri, uri, uri])
})
test('does not call listBlobs without a usable space ref', () => {
  for (const page of [{ spaces: [{ name: 'test' }] }, { spaces: [null] }, { spaces: [{ uri: '' }] }, { spaces: {} }])
    assert.throws(() => spaceRefs(page), /old server returned/)
})
