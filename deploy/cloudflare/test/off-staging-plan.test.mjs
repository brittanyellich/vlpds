import test from 'node:test';
import assert from 'node:assert/strict';
import {OFF_STAGE as P,offImage,rollbackDeployment,validateOffSnapshot,qualifyOffTransition,prepareOffStage,prepareOffStageConfig} from '../scripts/off-staging-plan.mjs';
const pairs=[["ADMIN_HOST","plain_text"],["ADMIN_TOKEN","secret_text"],["AGENT_A2A_ENABLED","plain_text"],["AGENT_A2A_RUNTIME","plain_text"],["CF_ACCOUNT_ID","secret_text"],["DEPLOY_TOKEN","secret_text"],["EMAIL_API_TOKEN","secret_text"],["EMAIL_API_URL","secret_text"],["EMAIL_FROM_ADDRESS","secret_text"],["ENABLED","plain_text"],["HANDLE_DOMAIN","plain_text"],["INTERNAL_TOKEN","secret_text"],["JWT_SECRET","secret_text"],["KEK","secret_text"],["OPERATOR_DID","plain_text"],["PDS","durable_object_namespace"],["PLC_RECOVERY_DID_KEY","secret_text"],["PLC_ROTATION_KEY_HEX","secret_text"],["PUBLIC_HOST","plain_text"],["S3_ACCESS_KEY","secret_text"],["S3_BUCKET","plain_text"],["S3_PREFIX","plain_text"],["S3_SECRET_KEY","secret_text"]];
const account='a'.repeat(32), nextWorker='11111111-1111-1111-1111-111111111111';
const bindings=()=>pairs.map(([name,type])=>({name,type,...(type==='plain_text'?{text:name==='AGENT_A2A_ENABLED'?'false':name==='AGENT_A2A_RUNTIME'?'native-profile-v1':'synthetic'}:{})}));
function fixture(){
 let time=100, reads=0, worker=P.worker, script=P.script,digest=P.rollback,current=P.rollback;
 const events=[],claimed=new Set();
 const snapshot=()=>({observedAt:time,contentHash:'b'.repeat(64),meta:{id:worker,scriptEtag:script,bindings:bindings()},status:{desired:offImage(account,digest),current:offImage(account,current),running:true},health:{ok:true,version:'1.3.0+'+(current===P.candidate?P.revision:P.rollbackRevision)},uiOk:true,cardStatus:404});
 const transport={snapshot:async()=>{reads++;events.push('read');return snapshot();},
  prepare:async pins=>({...pins,script:'b'.repeat(64)}),
  claim:async id=>{events.push('claim');if(claimed.has(id))return false;claimed.add(id);return true;},
  publish:async p=>{events.push('publish');digest=p.manifest;worker=nextWorker;script=p.script;return {...p,worker,scriptEtag:script};},
  restore:async body=>{events.push('restore');assert.deepEqual(body,rollbackDeployment());worker=P.worker;script=P.script;digest=P.rollback;},
  restart:async image=>{events.push('restart');assert.equal(image,offImage(account,digest));current=digest;return{status:202,body:{desired:image,starting:true,restarted:true}};},
  ready:async()=>{events.push('ready');return snapshot();}};
 const grant=operation=>({operation,id:operation==='stage'?'22222222-2222-2222-2222-222222222222':'33333333-3333-3333-3333-333333333333',candidate:P.candidate,rollbackWorker:P.worker,expiresAt:600,exclusiveWindow:true});
 return {transport,events,snapshot,grant,now:()=>time,setTime:v=>time=v,get reads(){return reads;},run(operation='stage',staged){return qualifyOffTransition({operation,grant:grant(operation),account,transport,now:()=>time,staged});}};
}
test('stage and exact-version rollback need independent OFF readiness after one accepted restart each',async()=>{
 const f=fixture(),staged=await f.run();assert.equal(staged.worker,nextWorker);assert.equal(staged.nativeOffSelfAttestation,false);
 const restored=await f.run('rollback',staged);assert.equal(restored.worker,P.worker);assert.equal(restored.digest,P.rollback);
 assert.deepEqual(f.events,['read','read','claim','read','publish','read','restart','ready','read','read','claim','read','restore','read','restart','ready']);
});
test('reject baseline drift, stale/future reads, extra bindings, lease, activation, health and image mismatch before writing',async()=>{
 const changes=[s=>s.meta.id=nextWorker,s=>s.meta.scriptEtag='b'.repeat(64),s=>s.observedAt=69,s=>s.observedAt=101,s=>s.meta.bindings.push({name:'OTHER',type:'plain_text'}),s=>s.meta.bindings.push({name:'AGENT_A2A_EXPIRES_AT',type:'plain_text',text:'999'}),s=>s.meta.bindings.find(b=>b.name==='AGENT_A2A_ENABLED').text='true',s=>s.status.current='other',s=>s.status.desired='other',s=>s.health.ok=false,s=>s.cardStatus=200];
 for(const change of changes){const f=fixture();f.transport.snapshot=async()=>{const s=f.snapshot();change(s);return s;};await assert.rejects(f.run());assert.deepEqual(f.events,[]);}
});
test('drift on final prewrite reread and expired or absent exclusive authority block all writes',async()=>{
 const f=fixture();let n=0;f.transport.snapshot=async()=>{const s=f.snapshot();if(++n===2)s.meta.bindings.find(b=>b.name==='S3_BUCKET').text='drift';return s;};await assert.rejects(f.run());assert.equal(f.events.length,0);
 for(const patch of [{expiresAt:100},{exclusiveWindow:false},{candidate:P.rollback},{rollbackWorker:nextWorker},{expiresAt:1000}]){const g=fixture();await assert.rejects(qualifyOffTransition({operation:'stage',grant:{...g.grant('stage'),...patch},account,transport:g.transport,now:g.now}));assert.equal(g.events.length,0);}
});
test('durable duplicate claim denies a second write even across a new invocation',async()=>{
 const f=fixture();await f.transport.claim(f.grant('stage').id);await assert.rejects(f.run());assert.equal(f.events.filter(x=>x==='publish').length,0);
});
test('ambiguous publish, drift after upload, bad ACK and readiness failure never replay or automatically roll back',async()=>{
 for(const phase of ['publish','selected','ack','ready','grant-expired']){
  const f=fixture();if(phase==='publish')f.transport.publish=async()=>{f.events.push('publish');throw new Error('ambiguous');};
  if(phase==='selected'){const snap=f.transport.snapshot;f.transport.snapshot=async()=>{const s=await snap();if(f.events.includes('publish'))s.status.desired='other';return s;};}
  if(phase==='ack')f.transport.restart=async()=>{f.events.push('restart');return{status:202,body:{starting:true}};};
  if(phase==='ready')f.transport.ready=async()=>{const s=f.snapshot();s.health.ok=false;return s;};
  if(phase==='grant-expired'){const snap=f.transport.snapshot;f.transport.snapshot=async()=>{const s=await snap();if(f.events.includes('publish'))f.setTime(600);return s;};}
  await assert.rejects(f.run());assert.equal(f.events.filter(x=>x==='publish').length,1);assert.ok(f.events.filter(x=>x==='restart').length<=1);assert.ok(!f.events.includes('restore'));
 }
});
test('rollback refuses unknown source Worker, ordinary-binding drift and absent provenance',async()=>{
 for(const patch of [{worker:P.worker},{worker:'wrong'},{ordinary:'0'.repeat(64)},{script:'0'.repeat(64)}]){const f=fixture();const staged=await f.run();const count=f.events.length;await assert.rejects(f.run('rollback',{...staged,...patch}));assert.ok(!f.events.slice(count).includes('restore'));}
 const f=fixture();await assert.rejects(f.run('rollback'));
});
test('registry image references accept only the two immutable digests and production config rejects synthetic account',()=>{
 assert.throws(()=>offImage(account,'latest'));assert.throws(()=>prepareOffStage({CLOUDFLARE_ACCOUNT_ID:account,DEPLOY_CONFIG:'{}'}));
 const f=fixture(),s=f.snapshot();assert.match(validateOffSnapshot(s,{account,worker:P.worker,digest:P.rollback,script:P.script,now:100}),/^[a-f0-9]{64}$/);
});

test('config projection pins existing candidate, preserves storage, rejects stale activation policy and keep_vars',()=>{
 const c={name:'crate-pds',account_id:account,main:'../src/index.ts',vars:{ENABLED:'true',PUBLIC_HOST:'pds.crate.social',HANDLE_DOMAIN:'crate.social',S3_BUCKET:'crate-pds',S3_PREFIX:'crate',ADMIN_HOST:'admin.crate.social',AGENT_A2A_ENABLED:'false',AGENT_A2A_RUNTIME:'native-profile-v1'},containers:[{class_name:'Pds',scheduling_policy:'durable_object',images:{pds:{image:offImage(account,P.rollback)}}}],durable_objects:{bindings:[{name:'PDS',class_name:'Pds'}]},routes:[{pattern:'admin.crate.social/*'}]};
 const env=config=>({DEPLOY_CONFIG:JSON.stringify(config),CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:'synthetic',DEPLOY_TOKEN:'a'.repeat(64)});
 const result=prepareOffStageConfig(env(c));assert.deepEqual(result.containers[0].images.pds,{image:offImage(account,P.candidate)});assert.deepEqual(result.durable_objects,c.durable_objects);assert.deepEqual(result.vars,c.vars);
 for(const patch of [{AGENT_A2A_EXPIRES_AT:'999'},{AGENT_A2A_ENABLED:'true'},{AGENT_A2A_REQUIRE_OWNER_CONSENT:'true'},{AGENT_A2A_KODY_TOKEN:'synthetic'}])assert.throws(()=>prepareOffStageConfig(env({...c,vars:{...c.vars,...patch}})));
 assert.throws(()=>prepareOffStageConfig(env({...c,keep_vars:true})));
});

test('prepared source and OCI identity bind publish ACK and selected script; never restart on mismatch',async()=>{
 for(const key of ['revision','manifest','ociConfig','script']){const f=fixture(),prepare=f.transport.prepare;f.transport.prepare=async pins=>({...await prepare(pins),[key]:'wrong'});await assert.rejects(f.run());assert.ok(!f.events.includes('publish'));}
 for(const key of ['revision','manifest','ociConfig','script']){const f=fixture(),publish=f.transport.publish;f.transport.publish=async pins=>({...await publish(pins),[key]:'wrong'});await assert.rejects(f.run());assert.ok(!f.events.includes('restart'));}
 const f=fixture(),snap=f.transport.snapshot;f.transport.snapshot=async()=>{const s=await snap();if(f.events.includes('publish'))s.meta.scriptEtag='c'.repeat(64);return s;};await assert.rejects(f.run());assert.ok(!f.events.includes('restart'));
});
