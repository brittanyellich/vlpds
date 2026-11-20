import { execFile } from 'node:child_process'
import { readFileSync, realpathSync, statSync } from 'node:fs'
import { isAbsolute, join, dirname } from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const run = promisify(execFile)
const assertionPath = fileURLToPath(new URL('./a2a-profile-assert.mjs', import.meta.url))
const expected = Object.freeze({
	kind: 'profile_asserted',
	profileId: 'prf_642a5cf465fa4528a8f7e075f29557c4',
	agentDid: 'did:plc:6tlvgafuonoighfrtpejff5m',
	principalDid: 'did:plc:exquicw7jew5vxerpgvc3x6w',
})

/** Resolve only a preinstalled, pinned CLI. Never search PATH or invoke npm. */
export function inspectCliEntry(cliEntry) {
	if (typeof cliEntry !== 'string' || !isAbsolute(cliEntry))
		throw new Error('Absolute CLI entry path required')
	let path, packagePath, manifest
	try {
		path = realpathSync(cliEntry)
		if (path !== cliEntry || !path.endsWith('/@kodycodes/cli/dist/bin.js') || !statSync(path).isFile())
			throw new Error('Unexpected CLI entry')
		packagePath = join(dirname(dirname(path)), 'package.json')
		manifest = JSON.parse(readFileSync(packagePath, 'utf8'))
	} catch {
		throw new Error('Pinned CLI artifact unavailable')
	}
	if (manifest.name !== '@kodycodes/cli' || manifest.version !== '3.46.2' ||
		manifest.bin?.kody !== 'dist/bin.js')
		throw new Error('Pinned CLI artifact mismatch')
	return path
}

/**
 * Private, host-owned invocation only. Never pass inbound input, proof, URLs,
 * profile selection, token, or CLI path from a request into this function.
 */
export async function dispatchProfileAssertionProduction({ token, cliEntry, home, execute = run } = {}) {
	if (typeof token !== 'string' || !token.startsWith('kody_at_'))
		throw new Error('Private profile token required')
	if (typeof home !== 'string' || !isAbsolute(home))
		throw new Error('Absolute private HOME required')
	const path = inspectCliEntry(cliEntry)
	let stdout
	try {
		const response = await execute(process.execPath, [path, 'execute', '--local', '--file', assertionPath], {
			env: { PATH: '/usr/bin:/bin', HOME: home, KODY_API_TOKEN: token },
			timeout: 60_000, maxBuffer: 64 * 1024,
		})
		stdout = response.stdout
	} catch {
		throw new Error('Profile assertion dispatch failed')
	}
	let result
	try { result = JSON.parse(stdout) }
	catch { throw new Error('Invalid profile assertion response') }
	if (!result || typeof result !== 'object' || Array.isArray(result) ||
		Object.keys(result).length !== Object.keys(expected).length ||
		Object.entries(expected).some(([key, value]) => result[key] !== value))
		throw new Error('Profile assertion mismatch')
	return { ...expected }
}
