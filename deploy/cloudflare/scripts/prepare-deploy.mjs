import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { validateArtifact, registryImage } from './verify-artifact.mjs';

export function prepareDeployment(env, artifact, { preflight = false } = {}) {
  const { DEPLOY_CONFIG, DEPLOY_TOKEN, CLOUDFLARE_ACCOUNT_ID: account, CLOUDFLARE_API_TOKEN,
    OPERATION, ROLLBACK_IMAGE } = env;
  if (!DEPLOY_CONFIG || !CLOUDFLARE_API_TOKEN || !/^[a-f0-9]{32}$/.test(account ?? '') ||
      !/^[a-f0-9]{64}$/.test(DEPLOY_TOKEN ?? '')) throw new Error('Missing/invalid production deployment credentials');
  const runtime = env.RUNTIME ?? 'pds-runtime';
  if (!['pds-runtime', 'agent-a2a'].includes(runtime)) throw new Error('Unsupported runtime');
  const config = JSON.parse(DEPLOY_CONFIG);
  if (config.name !== 'crate-pds' || config.account_id !== account ||
      !['src/index.ts', '../src/index.ts'].includes(config.main) || config.vars?.ENABLED !== 'true' ||
      config.vars?.PUBLIC_HOST !== 'pds.crate.social' || config.vars?.HANDLE_DOMAIN !== 'crate.social' ||
      config.vars?.S3_BUCKET !== 'crate-pds' || config.vars?.S3_PREFIX !== 'crate' ||
      config.vars?.ADMIN_HOST !== 'admin.crate.social' || config.containers?.length !== 1 ||
      config.containers[0].class_name !== 'Pds' || config.containers[0].scheduling_policy !== 'durable_object' ||
      !config.containers[0].images?.pds || Object.keys(config.containers[0].images).length !== 1 ||
      config.durable_objects?.bindings?.[0]?.name !== 'PDS' ||
      !config.routes?.some(r => r.pattern === 'admin.crate.social/*')) {
    throw new Error('Production configuration does not match the known live deployment');
  }
  // Stage capable images without activating anything. Secret provisioning and
  // activation require their own reviewed, explicitly approved workflow change.
  if (config.vars.AGENT_A2A_ENABLED !== undefined && config.vars.AGENT_A2A_ENABLED !== 'false') {
    throw new Error('Agent activation is not supported by this preparation workflow');
  }
  for (const name of ['AGENT_A2A_BRIDGE_KEY', 'AGENT_A2A_KODY_TOKEN']) {
    if (Object.hasOwn(config.vars, name)) throw new Error('Agent secrets must not be configuration vars');
  }
  config.main = 'src/index.ts';
  config.vars.AGENT_A2A_ENABLED = 'false';
  if (runtime === 'agent-a2a') config.vars.AGENT_A2A_RUNTIME = 'native-profile-v1';
  if (OPERATION === 'rollback' && runtime === 'pds-runtime') {
    registryImage(ROLLBACK_IMAGE, account);
    config.containers[0].images.pds = { image: ROLLBACK_IMAGE };
  } else if (OPERATION === 'deploy' && !ROLLBACK_IMAGE) {
    if (!/^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? '')) throw new Error('Exact source revision required');
    if (preflight) {
      config.containers[0].images.pds = { dockerfile: '../../Dockerfile', build_context: '../..',
        build_vars: { VLPDS_RUNTIME_STAGE: runtime, VLPDS_GIT_REV: env.GITHUB_SHA } };
      return config;
    }
    validateArtifact(artifact, runtime, env.GITHUB_SHA);
    if (artifact.remotePinVerified !== true || artifact.remoteConfigDigest !== artifact.configDigest) throw new Error('Remote content binding required');
    registryImage(artifact.uploadedRoot, account);
    registryImage(artifact.remoteImage, account);
    config.containers[0].images.pds = { image: artifact.remoteImage };
  } else throw new Error('Invalid operation, rollback image or runtime');
  return config;
}

export function verifyDesired(config, status) {
  const expected = config.containers?.[0]?.images?.pds?.image;
  if (typeof expected !== 'string' || status?.desired !== expected) throw new Error('Worker image differs from the verified pinned artifact; refuse restart');
  return expected;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv[2] === '--verify-desired') {
      const config = JSON.parse(readFileSync('.ci-deployment.json', 'utf8'));
      console.log(verifyDesired(config, JSON.parse(readFileSync(process.argv[3], 'utf8'))));
    } else if (process.argv[2] === '--preflight') {
      prepareDeployment(process.env, undefined, { preflight: true });
    } else {
      const artifact = process.env.OPERATION === 'deploy' && process.env.ARTIFACT_FILE
        ? JSON.parse(readFileSync(process.env.ARTIFACT_FILE, 'utf8')) : undefined;
      writeFileSync('.ci-deployment.json', JSON.stringify(prepareDeployment(process.env, artifact)), { mode: 0o600 });
    }
  } catch { console.error('Deployment preparation/image gate refused; inspect approved inputs without printing secrets'); process.exitCode = 1; }
}
