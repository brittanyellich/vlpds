import { writeFileSync } from 'node:fs';

const { DEPLOY_CONFIG, DEPLOY_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN, OPERATION, ROLLBACK_IMAGE } = process.env;
if (!DEPLOY_CONFIG || !CLOUDFLARE_API_TOKEN || !/^[a-f0-9]{32}$/.test(CLOUDFLARE_ACCOUNT_ID ?? '') ||
    !/^[a-f0-9]{64}$/.test(DEPLOY_TOKEN ?? '')) throw new Error('Missing/invalid production deployment credentials');
const config = JSON.parse(DEPLOY_CONFIG);
const image = config.containers?.[0]?.images?.pds;
if (config.name !== 'crate-pds' || config.account_id !== CLOUDFLARE_ACCOUNT_ID ||
    config.main !== 'src/index.ts' || config.vars?.ENABLED !== 'true' ||
    config.vars?.PUBLIC_HOST !== 'pds.crate.social' || config.vars?.HANDLE_DOMAIN !== 'crate.social' ||
    config.vars?.S3_BUCKET !== 'crate-pds' || config.vars?.S3_PREFIX !== 'crate' ||
    config.vars?.ADMIN_HOST !== 'admin.crate.social' ||
    config.containers?.length !== 1 || config.containers[0].class_name !== 'Pds' ||
    config.containers[0].scheduling_policy !== 'durable_object' || !image ||
    config.durable_objects?.bindings?.[0]?.name !== 'PDS' ||
    !config.routes?.some(r => r.pattern === 'admin.crate.social/*')) {
  throw new Error('Production configuration does not match the known live deployment');
}
if (OPERATION === 'rollback') {
  if (!/^registry\.cloudflare\.com\/[a-f0-9]{32}\/vlpds@sha256:[a-f0-9]{64}$/.test(ROLLBACK_IMAGE ?? '') ||
      !ROLLBACK_IMAGE.startsWith(`registry.cloudflare.com/${CLOUDFLARE_ACCOUNT_ID}/`)) {
    throw new Error('Rollback requires an earlier digest-pinned Cloudflare registry image in this account');
  }
  config.containers[0].images.pds = { image: ROLLBACK_IMAGE };
} else if (OPERATION === 'deploy' && !ROLLBACK_IMAGE) {
  config.containers[0].images.pds = { dockerfile: '../../Dockerfile', build_context: '../..' };
} else {
  throw new Error('Deploy must not set rollback_image');
}
writeFileSync('.ci-deployment.json', JSON.stringify(config), { mode: 0o600 });
