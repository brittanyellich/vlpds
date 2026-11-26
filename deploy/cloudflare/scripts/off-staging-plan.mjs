// Local qualification core. No CLI, credential lookup, network, or automatic
// workflow entry point. A future transport must implement the contracts below.
import {createHash} from 'node:crypto';
import {prepareDeployment} from './prepare-deploy.mjs';
import {checkBindings} from './pilot-provider.mjs';

export const OFF_STAGE=Object.freeze({
 revision:'703c118c66277ca42c45808a2f6cc620429c6718',
 candidate:'sha256:ea8627d4e368ca3bd3eafaf8c24765fa3db00c6f0c182853c4feda6bac47a488',
 config:'sha256:0c74fc9a23efdc50ea7b92359fe806ef0702dee29275f4a92337e9188c8e873a',
 rollback:'sha256:2e254f9394937be2141e192b715f88867a349bbd85c80d9279e435282b11161d',
 rollbackRevision:'21117d08d00b6d1bb95430c0cc4a89eb5ec59785',
 worker:'93724e8b-1a4e-41ab-ba5a-1759bfb8a0cc',
 script:'88f6a917a64c75dda70dd40bb76cc74c8607790400fd50349095ec7fe615dc42',
 types:'0fc25600babf6b573a96519018b704a676c59723f09f83ba89de0b27f3c0c5ad',
 accountHash:'b75b4505b1b8e6c4ab73fba1d8600691adb7be2cc8da2a77ee52d5e19c6e543e',
});
const fail=()=>new Error('OFF staging gate refused; reconcile read-only, do not replay');
const uuid=v=>typeof v==='string'&&/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v);
const sha=v=>createHash('sha256').update(v).digest('hex');
export function offImage(account,digest){
 if(!/^[a-f0-9]{32}$/.test(account??'')||![OFF_STAGE.candidate,OFF_STAGE.rollback].includes(digest))throw fail();
 return `registry.cloudflare.com/${account}/vlpds@${digest}`;
}
// Protected DEPLOY_CONFIG is preserved except for the exact image and OFF
// variables. Refuse stale policy/secrets instead of silently deleting them.
export function prepareOffStage(env){
 if(sha(env.CLOUDFLARE_ACCOUNT_ID??'')!==OFF_STAGE.accountHash)throw fail();
 return prepareOffStageConfig(env);
}
// Pure config projection, separately testable with a synthetic account. The
// production boundary must use prepareOffStage, not this unbound projection.
export function prepareOffStageConfig(env){
 const original=JSON.parse(env.DEPLOY_CONFIG);
 if(original.keep_vars===true)throw fail();
 const agent=Object.entries(original.vars??{}).filter(([k])=>k.startsWith('AGENT_A2A_'));
 if(agent.length!==2||!agent.some(([k,v])=>k==='AGENT_A2A_ENABLED'&&v==='false')||!agent.some(([k,v])=>k==='AGENT_A2A_RUNTIME'&&v==='native-profile-v1'))throw fail();
 return prepareDeployment({...env,OPERATION:'rollback',RUNTIME:'pds-runtime',ROLLBACK_IMAGE:offImage(env.CLOUDFLARE_ACCOUNT_ID,OFF_STAGE.candidate)});
}
export function rollbackDeployment(){
 // Supported Workers deployment API: select the existing version, never upload
 // current source and mislabel it a restoration of the old Worker.
 return {strategy:'percentage',versions:[{version_id:OFF_STAGE.worker,percentage:100}],code_update_strategy:'immediate'};
}
export function validateOffSnapshot(s,{account,worker,digest,script,ordinary,now,healthy=true}){
 if(!Number.isSafeInteger(now)||!Number.isSafeInteger(s?.observedAt)||s.observedAt>now||now-s.observedAt>30||!uuid(worker)||s.meta?.id!==worker)throw fail();
 if(script!==undefined&&s.meta.scriptEtag!==script)throw fail();
 if(!/^[a-f0-9]{64}$/.test(s.meta.scriptEtag??'')||s.meta.bindings?.length!==23)throw fail();
 const types=sha(JSON.stringify(s.meta.bindings.map(b=>[b.name,b.type]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0)));
 if(types!==OFF_STAGE.types)throw fail();
 const baseline=checkBindings(s.meta,{enabled:false,provisioned:false,baseline:ordinary});
 const image=offImage(account,digest);
 if(s.status?.desired!==image)throw fail();
 if(typeof s.status.running!=='boolean'||![null,offImage(account,OFF_STAGE.candidate),offImage(account,OFF_STAGE.rollback)].includes(s.status.current))throw fail();
 const revision=digest===OFF_STAGE.candidate?OFF_STAGE.revision:OFF_STAGE.rollbackRevision;
 if(healthy&&(s.status.current!==image||s.status.running!==true||s.health?.ok!==true||s.health.version!==`1.3.0+${revision}`||s.uiOk!==true||s.cardStatus!==404))throw fail();
 return baseline;
}

// Contracts are deliberately explicit: snapshot supplies independently fetched
// metadata/status/public health; prepare verifies fixed source/OCI pins and
// computes the upload's script hash without writes; claim durably claims this
// operation before any write; publish binds the Wrangler ACK to that preparation; restore selects
// the existing Worker version; restart returns the actual HTTP ACK; ready is a
// bounded GET-only observation (no restart retry). No transport is selected here.
export async function qualifyOffTransition({operation,grant,account,transport,now,staged}){
 // The caller owns account binding; prepareOffStage enforces the production
 // fingerprint. Synthetic transports use a synthetic account here.
 if(!['stage','rollback'].includes(operation)||!/^[a-f0-9]{32}$/.test(account??''))throw fail();
 const time=now();
 if(grant?.operation!==operation||grant.exclusiveWindow!==true||grant.candidate!==OFF_STAGE.candidate||grant.rollbackWorker!==OFF_STAGE.worker||!uuid(grant.id)||!Number.isSafeInteger(grant.expiresAt)||grant.expiresAt<=time||grant.expiresAt-time>600)throw fail();
 const sourceWorker=operation==='stage'?OFF_STAGE.worker:staged?.worker;
 const sourceDigest=operation==='stage'?OFF_STAGE.rollback:OFF_STAGE.candidate;
 if(!uuid(sourceWorker)||sourceWorker===OFF_STAGE.worker&&operation==='rollback'||operation==='rollback'&&!/^[a-f0-9]{64}$/.test(staged?.ordinary??''))throw fail();
 const before=await transport.snapshot();
 const ordinary=validateOffSnapshot(before,{account,worker:sourceWorker,digest:sourceDigest,script:operation==='stage'?OFF_STAGE.script:staged.script,ordinary:staged?.ordinary,now:now(),healthy:operation==='stage'});
 // A second authoritative read closes the local preparation gap. The API has
 // no compare-and-swap: the external exclusive write window remains required.
 const fresh=await transport.snapshot();
 validateOffSnapshot(fresh,{account,worker:sourceWorker,digest:sourceDigest,script:before.meta.scriptEtag,ordinary,now:now(),healthy:operation==='stage'});
 let prepared;
 if(operation==='stage'){
  prepared=await transport.prepare({revision:OFF_STAGE.revision,manifest:OFF_STAGE.candidate,ociConfig:OFF_STAGE.config});
  if(prepared?.revision!==OFF_STAGE.revision||prepared.manifest!==OFF_STAGE.candidate||prepared.ociConfig!==OFF_STAGE.config||!/^[a-f0-9]{64}$/.test(prepared.script??''))throw fail();
 }
 if(now()>=grant.expiresAt||await transport.claim(grant.id)!==true||now()>=grant.expiresAt)throw fail();
 const immediate=await transport.snapshot();
 validateOffSnapshot(immediate,{account,worker:sourceWorker,digest:sourceDigest,script:before.meta.scriptEtag,ordinary,now:now(),healthy:operation==='stage'});
 if(now()>=grant.expiresAt)throw fail();
 let worker,expectedScript;
 if(operation==='stage'){
  const published=await transport.publish(prepared);
  if(published?.script!==prepared.script||published.revision!==prepared.revision||published.manifest!==prepared.manifest||published.ociConfig!==prepared.ociConfig||!/^[a-f0-9]{64}$/.test(published.scriptEtag??''))throw fail();
  worker=published.worker;expectedScript=published.scriptEtag;
 }
 else {await transport.restore(rollbackDeployment());worker=OFF_STAGE.worker;}
 if(!uuid(worker)||operation==='stage'&&worker===OFF_STAGE.worker)throw fail();
 const target=operation==='stage'?OFF_STAGE.candidate:OFF_STAGE.rollback;
 const selected=await transport.snapshot();
 validateOffSnapshot(selected,{account,worker,digest:target,script:operation==='rollback'?OFF_STAGE.script:expectedScript,ordinary,now:now(),healthy:false});
 if(operation==='stage'&&selected.contentHash!==prepared.script)throw fail();
 // Check authority again immediately before the second write. A partially
 // completed transition must be reconciled; it never extends its own grant.
 if(now()>=grant.expiresAt)throw fail();
 const ack=await transport.restart(offImage(account,target));
 if(ack?.status!==202||ack.body?.desired!==offImage(account,target)||ack.body.starting!==true||typeof ack.body.restarted!=='boolean')throw fail();
 const after=await transport.ready();
 validateOffSnapshot(after,{account,worker,digest:target,script:selected.meta.scriptEtag,ordinary,now:now()});
 return {operation,worker,script:after.meta.scriptEtag,ordinary,digest:target,workerRestartAcknowledged:true,independentOffReadback:true,nativeOffSelfAttestation:false};
}
