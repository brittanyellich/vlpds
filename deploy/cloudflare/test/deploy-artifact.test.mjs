import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { prepareDeployment, verifyDesired } from '../scripts/prepare-deploy.mjs';
import { inspectArtifact, bindRemoteArtifact, validateArtifact } from '../scripts/verify-artifact.mjs';

const account = '1'.repeat(32), revision = '2'.repeat(40), id = 'sha256:' + '3'.repeat(64);
const rawManifest = Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{digest:id},layers:[]}));
const hash = b => 'sha256:' + createHash('sha256').update(b).digest('hex');
const child = hash(rawManifest);
const indexBytes = children => Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:children}));
const descriptor = {digest:child,size:rawManifest.length,platform:{os:'linux',architecture:'amd64'}};
const rawIndex = indexBytes([descriptor]), root = hash(rawIndex);
const remote = `registry.cloudflare.com/${account}/vlpds@${child}`;
const uploaded = `registry.cloudflare.com/${account}/vlpds@${root}`;
const base = runtime => ({ version: 1, runtime, revision, imageId: id, configDigest:id, dockerClientVersion:'29.7.2', platform: 'linux/amd64', capabilityVerified: true });
const bound = runtime => ({ ...base(runtime), remoteImage: remote, uploadedRoot: uploaded, remoteConfigDigest: id, remotePinVerified: true });
const config = () => ({ name: 'crate-pds', account_id: account, main: '../src/index.ts',
  vars: { ENABLED: 'true', PUBLIC_HOST: 'pds.crate.social', HANDLE_DOMAIN: 'crate.social', S3_BUCKET: 'crate-pds', S3_PREFIX: 'crate', ADMIN_HOST: 'admin.crate.social' },
  containers: [{ class_name: 'Pds', scheduling_policy: 'durable_object', images: { pds: { dockerfile: 'old', build_vars: { VLPDS_RUNTIME_STAGE: 'wrong' } } } }],
  durable_objects: { bindings: [{ name: 'PDS', class_name: 'Pds' }] },
  routes: [{ pattern: 'admin.crate.social/*' }, { pattern: 'pds.crate.social/*' }], migrations: [{ tag: 'existing' }],
});
const env = (runtime, c = config()) => ({ DEPLOY_CONFIG: JSON.stringify(c), DEPLOY_TOKEN: 'a'.repeat(64), CLOUDFLARE_API_TOKEN: 'fixture',
  CLOUDFLARE_ACCOUNT_ID: account, OPERATION: 'deploy', GITHUB_SHA: revision, ...(runtime ? { RUNTIME: runtime } : {}) });

test('ordinary is default; both runtimes pin only their verified artifact and preserve storage/routes', () => {
  for (const runtime of ['pds-runtime', 'agent-a2a']) {
    const original = config(), result = prepareDeployment(env(runtime === 'pds-runtime' ? undefined : runtime, original), bound(runtime));
    assert.deepEqual(result.containers[0].images.pds, { image: remote });
    assert.equal(result.vars.AGENT_A2A_ENABLED, 'false');
    assert.equal(result.main, 'src/index.ts');
    for (const k of ['account_id', 'routes', 'durable_objects', 'migrations']) assert.deepEqual(result[k], original[k]);
    assert.equal(result.vars.S3_BUCKET, 'crate-pds'); assert.equal(result.vars.S3_PREFIX, 'crate');
    if (runtime === 'agent-a2a') assert.equal(result.vars.AGENT_A2A_RUNTIME, 'native-profile-v1');
    const plan = prepareDeployment(env(runtime), undefined, {preflight:true});
    assert.deepEqual(plan.containers[0].images.pds.build_vars, {VLPDS_RUNTIME_STAGE:runtime,VLPDS_GIT_REV:revision});
  }
});
test('rejects mismatched, unbound, stale and foreign-account artifacts', () => {
  for (const change of [{runtime:'agent-a2a'}, {revision:'a'.repeat(40)}, {platform:'linux/arm64'}, {capabilityVerified:false},
    {remotePinVerified:false}, {remoteConfigDigest:child}, {remoteImage:remote.replace(account,'f'.repeat(32))}, {imageId:'mutable:tag'}]) {
    assert.throws(() => prepareDeployment(env(), { ...bound('pds-runtime'), ...change }));
  }
  assert.throws(() => prepareDeployment(env(), undefined));
  assert.throws(() => prepareDeployment(env('unknown'), bound('pds-runtime')));
  const extra = config(); extra.containers[0].images.other = {dockerfile:'unverified'};
  assert.throws(()=>prepareDeployment(env('agent-a2a',extra),bound('agent-a2a')));
});
test('fails closed on activation and secrets in vars; rollback stays off and digest-pinned', () => {
  for (const vars of [{AGENT_A2A_ENABLED:'true'}, {AGENT_A2A_KODY_TOKEN:'fixture'}, {AGENT_A2A_BRIDGE_KEY:'fixture'}]) {
    const c = config(); Object.assign(c.vars, vars); assert.throws(() => prepareDeployment(env('agent-a2a', c), bound('agent-a2a')));
  }
  const result = prepareDeployment({...env(), OPERATION:'rollback', ROLLBACK_IMAGE:remote});
  assert.deepEqual(result.containers[0].images.pds, {image:remote}); assert.equal(result.vars.AGENT_A2A_ENABLED,'false');
  assert.throws(() => prepareDeployment({...env('agent-a2a'), OPERATION:'rollback', ROLLBACK_IMAGE:remote}));
  assert.throws(() => prepareDeployment({...env(), OPERATION:'rollback', ROLLBACK_IMAGE:remote.split('@')[0]+':latest'}));
});
test('ties exact registry index/child bytes to the exported config and refuses tampering or tag races', () => {
  const local = {Id:id, RepoDigests:[uploaded]};
  const fetcher = ref => {assert.equal(ref,remote);return rawManifest;};
  assert.deepEqual(bindRemoteArtifact(base('agent-a2a'),local,rawIndex,account,fetcher),bound('agent-a2a'));
  assert.deepEqual(bindRemoteArtifact(base('agent-a2a'),local,Buffer.concat([rawIndex,Buffer.from('\n')]),account,fetcher),bound('agent-a2a'));
  assert.throws(()=>bindRemoteArtifact(base('agent-a2a'),{...local,Id:child},rawIndex,account,fetcher));
  assert.throws(()=>bindRemoteArtifact(base('agent-a2a'),local,Buffer.from('{}'),account,fetcher));
  assert.throws(()=>bindRemoteArtifact(base('agent-a2a'),local,rawIndex,account,()=>Buffer.from('{}')));
  const duplicate=indexBytes([descriptor,descriptor]);
  assert.throws(()=>bindRemoteArtifact(base('agent-a2a'),{...local,RepoDigests:[uploaded.split('@')[0]+'@'+hash(duplicate)]},duplicate,account,fetcher));
  const otherPlatform=indexBytes([{...descriptor,platform:{os:'linux',architecture:'arm64'}}]);
  assert.throws(()=>bindRemoteArtifact(base('agent-a2a'),{...local,RepoDigests:[uploaded.split('@')[0]+'@'+hash(otherPlatform)]},otherPlatform,account,fetcher));
  assert.throws(()=>bindRemoteArtifact({...base('agent-a2a'),configDigest:child},local,rawIndex,account,fetcher));
});
test('captured actual OCI raw bytes verify a config digest distinct from Docker29 image ID', () => {
  const actual=JSON.parse(readFileSync(new URL('./fixtures/docker29-oci-inspect.json',import.meta.url)));
  const bytes=Buffer.from(actual.Raw,'base64'),configDigest=actual.OCIManifest.config.digest,imageId=actual.Descriptor.digest;
  assert.notEqual(configDigest,imageId);
  const ref=uploaded.split('@')[0]+'@'+imageId;
  const a={...base('pds-runtime'),configDigest,imageId};
  const result=bindRemoteArtifact(a,{Id:imageId,RepoDigests:[ref]},bytes,account);
  assert.equal(result.remoteImage,ref);assert.equal(result.remoteConfigDigest,configDigest);
  assert.throws(()=>bindRemoteArtifact(a,{Id:imageId,RepoDigests:[ref]},JSON.stringify(actual.OCIManifest),account));
});
test('refuses restart if Worker desired image differs even when otherwise healthy', () => {
  const c = prepareDeployment(env(), bound('pds-runtime'));
  assert.equal(verifyDesired(c,{desired:remote,running:true,current:remote}),remote);
  assert.throws(() => verifyDesired(c,{desired:uploaded,running:true,current:uploaded}));
});
test('capability gate executes immutable image IDs and refuses wrong entrypoint/revision or missing native option', () => {
  const calls = [], info = {Id:id,Os:'linux',Architecture:'amd64',Config:{User:'vlpds:vlpds',Env:[`VLPDS_GIT_REV=${revision}`],
    Labels:{'io.atagents.runtime':'pds-runtime','org.opencontainers.image.revision':revision},Entrypoint:['/usr/bin/tini','--','vlpds']}};
  const run = args => { calls.push(args); if(args[0]==='version') return '"29.7.2"'; if(args[0]==='buildx') return '--raw'; if(args[0]==='image') return JSON.stringify([info]); return args.includes('--help') ? '--agent-a2a-config' : ''; };
  assert.deepEqual(inspectArtifact('mutable:build','pds-runtime',revision,run,()=>id),base('pds-runtime'));
  assert.ok(calls.filter(a=>a[0]==='run').every(a=>a.includes(id)&&!a.includes('mutable:build')));
  info.Config.Entrypoint=['node'];assert.throws(()=>inspectArtifact('build','pds-runtime',revision,run,()=>id));
  info.Config.Entrypoint=['/usr/bin/tini','--','vlpds']; info.Config.Labels['org.opencontainers.image.revision']='a'.repeat(40);
  assert.throws(()=>inspectArtifact('build','pds-runtime',revision,run,()=>id));
  info.Config.Labels['org.opencontainers.image.revision']=revision;
  assert.throws(()=>inspectArtifact('build','pds-runtime',revision,args=>args[0]==='version'?'"29.7.2"':args[0]==='buildx'?'--raw':args[0]==='image'?JSON.stringify([info]):'',()=>id));
  assert.throws(()=>validateArtifact(base('agent-a2a'),'pds-runtime',revision));
  assert.throws(()=>inspectArtifact('build','pds-runtime',revision,args=>args[0]==='version'?'"27.5.0"':run(args),()=>id));
});
test('agent image requires matching profile files, pinned CLI/workerd and opt-in supervisor readiness', () => {
  const info = {Id:id,Os:'linux',Architecture:'amd64',Config:{User:'vlpds:vlpds',Env:[`VLPDS_GIT_REV=${revision}`],
    Labels:{'io.atagents.runtime':'agent-a2a','org.opencontainers.image.revision':revision},
    Entrypoint:['/usr/bin/tini','--','/usr/local/bin/node','/opt/agent-contact-pilot/production/supervisor.mjs']}};
  let broken = '';
  const run = args => {
    if(args[0]==='version') return '"29.7.2"'; if(args[0]==='buildx') return '--raw'; if(args[0]==='image') return JSON.stringify([info]);
    if(args.includes('/usr/bin/sha256sum')) return broken==='hash' ? 'bad hash' : [
      '45500d83afc079361af1a8e0eaf9b5da994b11f248d486cca6ba99dd59eb2b28  /opt/agent-contact-pilot/production/a2a-profile-assert.mjs',
      '848fb40c1ded70137f97d4c3ba096f84554cef8fcda74790230a5c56ac5ee90b  /opt/agent-contact-pilot/production/a2a-profile-dispatch-production.mjs',
      'f29a9f6cbc09301cd4cdff8606549c8e017dffbdbbdcff24c89235ca64d7faa9  /opt/agent-contact-pilot/production/a2a-profile-runtime/package-lock.json',
    ].join('\n');
    if(args.some(a=>a.endsWith('/workerd'))) return broken==='workerd' ? 'wrong' : 'workerd 2026-08-15';
    if(args.some(a=>a.endsWith('/dist/bin.js'))) return broken==='cli' ? '3.0.0' : '3.46.2';
    return broken==='supervisor' && args.includes('-e') ? '' : '--agent-a2a-config';
  };
  assert.deepEqual(inspectArtifact('build','agent-a2a',revision,run,()=>id),base('agent-a2a'));
  for (broken of ['hash','workerd','cli','supervisor']) assert.throws(()=>inspectArtifact('build','agent-a2a',revision,run,()=>id));
});

test('operator consent selection is strict, default-off and reset on ordinary rollback',()=>{
 for(const value of [undefined,'false','true']){
  const c=config();if(value!==undefined)c.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT=value;
  const result=prepareDeployment(env('agent-a2a',c),bound('agent-a2a'));
  assert.equal(result.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT,value);
  assert.equal(result.vars.AGENT_A2A_ENABLED,'false');
  const rolled=prepareDeployment({...env('pds-runtime',c),OPERATION:'rollback',ROLLBACK_IMAGE:remote});
  assert.equal(rolled.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT,undefined);
  assert.equal(rolled.vars.AGENT_A2A_ENABLED,'false');
 }
 for(const value of [true,false,null,1,'TRUE','']){
  const c=config();c.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT=value;
  assert.throws(()=>prepareDeployment(env('agent-a2a',c),bound('agent-a2a')));
 }
 const c=config();c.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT='true';
 assert.throws(()=>prepareDeployment(env('pds-runtime',c),bound('pds-runtime')));
});
