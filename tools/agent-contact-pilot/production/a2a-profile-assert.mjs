import { kody } from 'kody:runtime'

// Fixed, read-only profile assertion. No caller parameters, public fetches,
// repository parser, credentials, or arbitrary execution are accepted here.
export default async function main() {
	const actor = await kody.metaGetCurrentUser({})
	if (actor.profile?.id !== 'prf_642a5cf465fa4528a8f7e075f29557c4')
		throw new Error('Kody run is not bound to the identity-test profile')
	return {
		kind: 'profile_asserted',
		profileId: 'prf_642a5cf465fa4528a8f7e075f29557c4',
		agentDid: 'did:plc:6tlvgafuonoighfrtpejff5m',
		principalDid: 'did:plc:exquicw7jew5vxerpgvc3x6w',
	}
}
