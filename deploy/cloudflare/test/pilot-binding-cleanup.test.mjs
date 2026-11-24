import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';
import{reconcileBindings,deleteOnlyPilotBindings,CLEANUP}from'../scripts/pilot-binding-cleanup.mjs';import{PILOT}from'../scripts/pilot-activation-plan.mjs';
const pairs=[["ADMIN_HOST","plain_text"],["ADMIN_TOKEN","secret_text"],["AGENT_A2A_ENABLED","plain_text"],["AGENT_A2A_RUNTIME","plain_text"],["CF_ACCOUNT_ID","secret_text"],["DEPLOY_TOKEN","secret_text"],["EMAIL_API_TOKEN","secret_text"],["EMAIL_API_URL","secret_text"],["EMAIL_FROM_ADDRESS","secret_text"],["ENABLED","plain_text"],["HANDLE_DOMAIN","plain_text"],["INTERNAL_TOKEN","secret_text"],["JWT_SECRET","secret_text"],["KEK","secret_text"],["OPERATOR_DID","plain_text"],["PDS","durable_object_namespace"],["PLC_RECOVERY_DID_KEY","secret_text"],["PLC_ROTATION_KEY_HEX","secret_text"],["PUBLIC_HOST","plain_text"],["S3_ACCESS_KEY","secret_text"],["S3_BUCKET","plain_text"],["S3_PREFIX","plain_text"],["S3_SECRET_KEY","secret_text"]];
test('cleanup pin matches authenticated OFF inspection and refuses the prior incident Worker',async()=>{
 assert.equal(CLEANUP.worker,'e7ba115b-d6f0-4c71-87e6-57040e8f8c41');
 const f=fixture({worker:'7495c31c-de99-40f5-a4a6-748026fd9425'});const result=await reconcileBindings({...f,operation:'cleanup',exclusiveWindow:true});
 assert.equal(result.result,'failed');assert.equal(result.failedStage,'expected-worker');assert.equal(f.calls,0);
});
function fixture({enabled=false,worker=CLEANUP.worker,script=CLEANUP.script,clean=false,changeAfter=false}={}){
 let provisioned=!clean,calls=0,time=0;const events=[];
 const bindings=()=>[...pairs.map(([name,type])=>({name,type,...(type==='plain_text'?{text:name==='AGENT_A2A_ENABLED'?String(enabled):name==='AGENT_A2A_RUNTIME'?'native-profile-v1':'synthetic'}:{})})),...(provisioned?['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'].map(name=>({name,type:'secret_text'})):[])];
 const provider={status:async()=>{events.push('status');},metadata:async()=>{const b=bindings();if(changeAfter&&calls)b[0].text='drift';return{id:worker,scriptEtag:script,bindings:b};},publicChecks:async flag=>{assert.equal(flag,false);events.push('health-off');}};
 const remove=async()=>{calls++;events.push('delete');provisioned=false;return true;};
 return {provider,remove,now:()=>time,sleep:async ms=>{time+=ms;},events,get calls(){return calls;},setProvisioned:v=>{provisioned=v;}};
}
test('exact OFF gate before one deletion; readback preserves ordinary bindings and exact image checks',async()=>{
 const f=fixture();const r=await reconcileBindings({...f,operation:'cleanup',exclusiveWindow:true});assert.equal(r.result,'verified-clean');assert.equal(r.offVerified,true);assert.equal(f.calls,1);assert.equal(r.checks[0].enabledFalse,true);assert.equal(r.checks.at(-1).bindingCount,23);assert.ok(f.events.indexOf('health-off')<f.events.indexOf('delete'));
});
test('inspect and already-clean paths never delete; unexpected Worker/code/ON state deny deletion',async()=>{
 const inspect=fixture();assert.equal((await reconcileBindings({...inspect,operation:'inspect'})).result,'off-with-pilot-bindings');assert.equal(inspect.calls,0);
 const clean=fixture({clean:true,worker:'00000000-0000-0000-0000-000000000000'});assert.equal((await reconcileBindings({...clean,operation:'cleanup',exclusiveWindow:true})).result,'already-clean');assert.equal(clean.calls,0);
 for(const opt of[{enabled:true},{worker:'00000000-0000-0000-0000-000000000000'},{script:'0'.repeat(64)}]){const f=fixture(opt);const r=await reconcileBindings({...f,operation:'cleanup',exclusiveWindow:true});assert.equal(r.result,'failed');assert.equal(f.calls,0);assert.equal(r.deleteAttempted,false);}
});
test('ambiguous deletion is reconciled with reads, never replayed; unrelated drift fails',async()=>{
 const f=fixture();let calls=0;const r=await reconcileBindings({...f,operation:'cleanup',exclusiveWindow:true,remove:async()=>{calls++;f.setProvisioned(false);throw new Error('RAW_SECRET');}});assert.equal(r.result,'verified-clean');assert.equal(r.deleteAcknowledged,false);assert.equal(calls,1);assert.ok(!JSON.stringify(r).includes('RAW_SECRET'));
 const drift=fixture({changeAfter:true});const d=await reconcileBindings({...drift,operation:'cleanup',exclusiveWindow:true});assert.equal(d.result,'failed');assert.equal(d.failedStage,'unchanged-ordinary-bindings');assert.equal(drift.calls,1);
});
test('fixed secret API payload contains only null for the two owned keys, no retry/redirect',async()=>{
 let calls=0;const provider={api:`https://api.cloudflare.com/client/v4/accounts/${'a'.repeat(32)}/workers/scripts/crate-pds`,cfToken:'c'.repeat(40)};
 assert.equal(await deleteOnlyPilotBindings(async(url,r)=>{calls++;assert.equal(url,provider.api+'/secrets-bulk');assert.equal(r.method,'PATCH');assert.equal(r.redirect,'error');assert.deepEqual(JSON.parse(r.body),{secrets:{AGENT_A2A_BRIDGE_KEY:null,AGENT_A2A_KODY_TOKEN:null}});return new Response('{"success":true}',{headers:{'content-type':'application/json'}});},provider),true);assert.equal(calls,1);
 assert.equal(await deleteOnlyPilotBindings(async()=>{calls++;throw new Error('RAW_SECRET');},provider),false);assert.equal(calls,2);
 assert.equal(await deleteOnlyPilotBindings(async()=>{calls++;},{...provider,api:'https://other.invalid'}),false);assert.equal(calls,2);
});
test('cleanup workflow has no installation/deploy/restart/profile token and only three existing secret references',()=>{
 const w=readFileSync(new URL('../../../.github/workflows/cloudflare-pilot-cleanup.yml',import.meta.url),'utf8');assert.match(w,/default: inspect/);assert.match(w,/github.run_attempt == 1/);assert.ok(!/VLPDS_AGENT_KODY_TOKEN|VLPDS_AGENT_BRIDGE_KEY|npm |wrangler |docker |pilot-runner\.mjs/.test(w));assert.equal((w.match(/\$\{\{ secrets\./g)||[]).length,3);
});

test('cleanup requires explicit exclusive-writer attestation and final version readback; no atomic claim',async()=>{
 const f=fixture();const denied=await reconcileBindings({...f,operation:'cleanup'});assert.equal(denied.result,'failed');assert.equal(denied.failedStage,'exclusive-writer-window');assert.equal(f.calls,0);assert.equal(denied.atomicApiPrecondition,false);
 const changed=fixture();let reads=0;const meta=changed.provider.metadata;changed.provider.metadata=async()=>{const m=await meta();if(++reads>1)m.id='00000000-0000-0000-0000-000000000000';return m;};const r=await reconcileBindings({...changed,operation:'cleanup',exclusiveWindow:true});assert.equal(r.result,'failed');assert.equal(r.failedStage,'fresh-worker-confirmation');assert.equal(changed.calls,0);
});

test('readback observes propagation after30s within the declared90s window without another delete',async()=>{
 const f=fixture();let attempts=0;const metadata=f.provider.metadata;f.provider.metadata=async()=>{if(f.now()>=30000)f.setProvisioned(false);return metadata();};
 const r=await reconcileBindings({...f,operation:'cleanup',exclusiveWindow:true,remove:async()=>{attempts++;return true;}});assert.equal(r.result,'verified-clean');assert.equal(attempts,1);assert.ok(f.now()>=30000&&f.now()<90000);
});
