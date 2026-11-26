import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const sha = /^sha256:[a-f0-9]{64}$/;
const revisionPattern = /^[a-f0-9]{40}$/;
function supportedClient(version) {
  return typeof version === 'string' && /^(?:28|29|[3-9]\d|[1-9]\d{2,})\.\d+\.\d+(?:[-+].*)?$/.test(version);
}
const hashes = {
  '/opt/agent-contact-pilot/production/a2a-profile-assert.mjs': '45500d83afc079361af1a8e0eaf9b5da994b11f248d486cca6ba99dd59eb2b28',
  '/opt/agent-contact-pilot/production/a2a-profile-dispatch-production.mjs': '848fb40c1ded70137f97d4c3ba096f84554cef8fcda74790230a5c56ac5ee90b',
  '/opt/agent-contact-pilot/production/a2a-profile-runtime/package-lock.json': 'f29a9f6cbc09301cd4cdff8606549c8e017dffbdbbdcff24c89235ca64d7faa9',
};
export function registryImage(image, account) {
  if (!/^[a-f0-9]{32}$/.test(account ?? '') || typeof image !== 'string' ||
      !new RegExp(`^registry\\.cloudflare\\.com/${account}/(?:vlpds|crate-pds-pds-pds)@sha256:[a-f0-9]{64}$`).test(image)) {
    throw new Error('Exact managed-registry image digest in the approved account required');
  }
  return image;
}
export function validateArtifact(a, runtime, revision) {
  if (!['pds-runtime', 'agent-a2a'].includes(runtime) || !revisionPattern.test(revision ?? '') ||
      !a || a.version !== 1 || a.runtime !== runtime || a.revision !== revision ||
      !sha.test(a.imageId ?? '') || !sha.test(a.configDigest ?? '') || !supportedClient(a.dockerClientVersion) ||
      a.platform !== 'linux/amd64' || a.capabilityVerified !== true) {
    throw new Error('Artifact revision, runtime, platform or capability gate refused');
  }
  return a;
}
const docker = args => execFileSync('docker', args, { encoding: 'utf8', timeout: 90000, maxBuffer: 2 * 1024 * 1024 });
function exportedConfigDigest(imageId) {
  const dir = mkdtempSync(join(tmpdir(), 'vlpds-artifact-'));
  try {
    const archive = join(dir, 'image.tar');
    docker(['image', 'save', '--platform', 'linux/amd64', '--output', archive, imageId]);
    const tar = path => execFileSync('tar', ['-xOf', archive, path], { timeout: 90000, maxBuffer: 2 * 1024 * 1024 });
    const manifest = JSON.parse(tar('manifest.json'));
    if (!Array.isArray(manifest) || manifest.length !== 1 ||
        !/^(?:blobs\/sha256\/[a-f0-9]{64}|[a-f0-9]{64}\.json)$/.test(manifest[0].Config ?? '')) throw new Error('Single exported config required');
    const raw = tar(manifest[0].Config), config = JSON.parse(raw);
    if (config.architecture !== 'amd64' || config.os !== 'linux') throw new Error('Exported config platform mismatch');
    return 'sha256:' + createHash('sha256').update(raw).digest('hex');
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
export function inspectArtifact(image, runtime, revision, run = docker, configDigestFor = exportedConfigDigest) {
  if (!['pds-runtime', 'agent-a2a'].includes(runtime) || !revisionPattern.test(revision ?? '')) throw new Error('Invalid build selection');
  // Platform-selective image export requires Docker28+. Buildx raw inspection
  // avoids depending on version-specific verbose JSON fields.
  const dockerClientVersion = JSON.parse(run(['version', '--format', '{{json .Client.Version}}']));
  if (!supportedClient(dockerClientVersion)) throw new Error('Docker CLI 28+ required for platform config export');
  if (!run(['buildx', 'imagetools', 'inspect', '--help']).includes('--raw')) throw new Error('Buildx raw manifest support required');
  const info = JSON.parse(run(['image', 'inspect', image]))[0];
  if (!sha.test(info?.Id ?? '') || info.Os !== 'linux' || info.Architecture !== 'amd64' ||
      info.Config?.User !== 'vlpds:vlpds' || info.Config?.Labels?.['io.atagents.runtime'] !== runtime ||
      info.Config?.Labels?.['org.opencontainers.image.revision'] !== revision ||
      !info.Config?.Env?.includes(`VLPDS_GIT_REV=${revision}`)) throw new Error('Image identity/capability label refused');
  const expected = runtime === 'agent-a2a'
    ? ['/usr/bin/tini', '--', '/usr/local/bin/node', '/opt/agent-contact-pilot/production/supervisor.mjs']
    : ['/usr/bin/tini', '--', 'vlpds'];
  if (JSON.stringify(info.Config.Entrypoint) !== JSON.stringify(expected)) throw new Error('Artifact entrypoint refused');
  // Every run uses the immutable inspected image ID, never the mutable build tag.
  const base = ['run', '--rm', '--platform', 'linux/amd64', '--network', 'none', '--read-only', '--tmpfs', '/tmp'];
  const help = run([...base, info.Id, '--help']);
  if (!help.includes('--agent-a2a-config')) throw new Error('Native agent route capability missing');
  if (runtime === 'pds-runtime') {
    run([...base, '--entrypoint', '/bin/sh', info.Id, '-c', 'test ! -e /usr/local/bin/node && test ! -e /opt/agent-contact-pilot']);
  } else {
    const got = run([...base, '--entrypoint', '/usr/bin/sha256sum', info.Id, ...Object.keys(hashes)]);
    const lines = got.trim().split('\n');
    if (lines.length !== Object.keys(hashes).length || new Set(lines.map(line => line.trim().split(/\s+/)[1])).size !== lines.length || lines.some(line => {
      const [hash, file] = line.trim().split(/\s+/); return hashes[file] !== hash;
    })) throw new Error('Profile artifact hash mismatch');
    const cli = '/opt/agent-contact-pilot/production/a2a-profile-runtime/node_modules/@kodycodes/cli/dist/bin.js';
    if (run([...base, '--entrypoint', '/usr/local/bin/node', info.Id, cli, '--version']).trim() !== '3.46.2') throw new Error('Pinned CLI missing');
    // Prove the baked workerd and supervisor/bridge can start without a real token or network.
    if (!run([...base, '--entrypoint', '/opt/agent-home/.cache/kody/workerd/1.20260815.1-linux-64/workerd', info.Id, '--version']).includes('2026-08-15')) throw new Error('Baked workerd missing');
    const enabledHelp = run([...base,
      '-e', 'VLPDS_AGENT_A2A_ENABLED=true', '-e', 'VLPDS_AGENT_A2A_REQUIRE_OWNER_CONSENT=true', '-e', 'VLPDS_AGENT_A2A_CALLER=did:plc:vsgwub3c3pupqt3yhxfmecma',
      '-e', `VLPDS_AGENT_BRIDGE_KEY=${'a'.repeat(64)}`, '-e', 'VLPDS_AGENT_KODY_TOKEN=kody_at_SYNTHETIC_ARTIFACT_CHECK',
      '-e', 'VLPDS_AGENT_A2A_SIGNED_CARD={"helpOnly":true}', '-e', 'VLPDS_AGENT_A2A_CARD_KEY=zSyntheticPublicPin', info.Id, '--help']);
    if (!enabledHelp.includes('--agent-a2a-config')) throw new Error('Opt-in supervisor readiness missing');
  }
  const configDigest = configDigestFor(info.Id);
  if (!sha.test(configDigest)) throw new Error('Exported config digest missing');
  return { version: 1, imageId: info.Id, configDigest, dockerClientVersion, runtime, revision, platform: 'linux/amd64', capabilityVerified: true };
}

// Authenticate exact manifest bytes by digest. Some CLI versions append one
// display newline; removing it is allowed only when the expected hash proves it.
function manifestBytes(value, digest, size) {
  const bytes = Buffer.from(value);
  const candidates = [bytes];
  if (bytes.at(-1) === 10) candidates.push(bytes.subarray(0, -1));
  const raw = candidates.find(b => (size === undefined || b.length === size) &&
    'sha256:' + createHash('sha256').update(b).digest('hex') === digest);
  if (!raw) throw new Error('Exact registry manifest bytes unavailable');
  const parsed = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(raw));
  if (parsed.schemaVersion !== 2) throw new Error('Unsupported manifest schema');
  return parsed;
}
export function bindRemoteArtifact(a, inspection, rootBytes, account, fetchManifest) {
  validateArtifact(a, a.runtime, a.revision);
  if (inspection?.Id !== a.imageId) throw new Error('Build tag changed after verification');
  const roots = (inspection.RepoDigests ?? []).filter(ref => {
    try { registryImage(ref, account); return true; } catch { return false; }
  });
  if (roots.length !== 1) throw new Error('One exact pushed registry reference required');
  const repository = roots[0].split('@')[0];
  let remoteImage = roots[0], manifest = manifestBytes(rootBytes, roots[0].split('@')[1]);
  if (['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'].includes(manifest.mediaType)) {
    if (!Array.isArray(manifest.manifests) || manifest.manifests.length > 32) throw new Error('Invalid registry index');
    const children = manifest.manifests.filter(m => m.platform?.os === 'linux' && m.platform?.architecture === 'amd64');
    if (children.length !== 1 || !sha.test(children[0].digest ?? '') || !Number.isSafeInteger(children[0].size) || children[0].size <= 0) {
      throw new Error('One exact AMD64 platform manifest required');
    }
    const child = children[0]; remoteImage = repository + '@' + child.digest;
    manifest = manifestBytes(fetchManifest(remoteImage), child.digest, child.size);
  }
  if (!['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'].includes(manifest.mediaType) ||
      manifest.config?.digest !== a.configDigest) throw new Error('Registry config does not match inspected artifact');
  registryImage(remoteImage, account);
  return { ...a, uploadedRoot: roots[0], remoteImage, remoteConfigDigest: a.configDigest, remotePinVerified: true };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [operation, image, file] = process.argv.slice(2);
    if (!image || !file) throw new Error('Usage: verify-artifact.mjs inspect|pin IMAGE REPORT_FILE');
    let report;
    if (operation === 'inspect') report = inspectArtifact(image, process.env.RUNTIME ?? 'pds-runtime', process.env.GITHUB_SHA);
    else if (operation === 'pin') {
      const a = JSON.parse(readFileSync(file, 'utf8'));
      const info = JSON.parse(docker(['image', 'inspect', image]))[0];
      const refs = (info.RepoDigests ?? []).filter(r => r.startsWith(`registry.cloudflare.com/${process.env.CLOUDFLARE_ACCOUNT_ID}/`));
      if (refs.length !== 1) throw new Error('Pushed reference missing or ambiguous');
      report = bindRemoteArtifact(a, info, docker(['buildx', 'imagetools', 'inspect', '--raw', refs[0]]), process.env.CLOUDFLARE_ACCOUNT_ID, ref => docker(['buildx', 'imagetools', 'inspect', '--raw', ref]));
    } else throw new Error('Unknown artifact operation');
    writeFileSync(file, JSON.stringify(report), { mode: 0o600 });
  } catch { console.error('Artifact verification failed; no publish/restart is permitted'); process.exitCode = 1; }
}
