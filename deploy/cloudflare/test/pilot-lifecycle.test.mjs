import test from 'node:test';import assert from 'node:assert/strict';
import{PilotLifecycle}from'../scripts/pilot-lifecycle.mjs';import{PILOT}from'../scripts/pilot-activation-plan.mjs';import{ProviderPending}from'../scripts/pilot-provider.mjs';
function fixture(){
 let state,enabled=false,provisioned=false,version=PILOT.offWorker,time=1800000000;const events=[];
 const card='{"synthetic":true}',identity={repository:'brittanyellich/vlpds',runId:123,head:'a'.repeat(40)};
 const metadata=()=>({id:version,scriptEtag:'e'.repeat(64),bindings:[{name:'PUBLIC_HOST',type:'plain_text',text:'pds.crate.social'},
 ...Object.entries({AGENT_A2A_ENABLED:enabled?'true':'false',AGENT_A2A_RUNTIME:'native-profile-v1',...(enabled?{AGENT_A2A_EXPIRES_AT:String(state?.deadline),AGENT_A2A_CALLER_DID:PILOT.caller,AGENT_A2A_CAPACITY:'1000',AGENT_A2A_SIGNED_CARD_JSON:card,AGENT_A2A_CARD_KEY_MULTIBASE:PILOT.cardKey}:{})}).map(([name,text])=>({name,text,type:'plain_text'})),
 ...(provisioned?['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'].map(name=>({name,type:'secret_text'})):[])]});
 const provider={image:`registry.cloudflare.com/${'a'.repeat(32)}/vlpds@${PILOT.digest}`,status:async()=>{events.push('status');},currentCardKey:async()=>PILOT.cardKey,metadata:async()=>metadata(),publicChecks:async e=>{assert.equal(e,enabled);return {bytes:Buffer.from(card)};},restart:async phase=>{events.push('restart:'+phase);}};
 const lifecycle=new PilotLifecycle({provider,save:async s=>{state=structuredClone(s);events.push('save:'+s.phase);},load:async()=>structuredClone(state),deploy:async e=>{events.push('deploy:'+e);enabled=e;version=e?'a'.repeat(36):'b'.repeat(36);return version;},
 introspect:async(token,o)=>{assert.equal(token,'kody_at_SYNTHETIC_ONLY');events.push('introspect');return o.expected;},provision:async x=>{assert.ok(x.stdin.includes('SYNTHETIC'));events.push('provision');provisioned=true;version='c'.repeat(36);return true;},remove:async()=>{events.push('remove');provisioned=false;},card,now:()=>time,sleep:async ms=>{time+=ms/1000;},identity});
 const credential={id:'synthetic_opaque_id',idleSeconds:900,maxSeconds:3600,orgBinding:'org',profileId:PILOT.profile,scopes:['org:execute'],issuedAt:time,expiresAt:time+900,maxExpiresAt:time+3600};
 return {lifecycle,provider,events,credential,get state(){return state;},get enabled(){return enabled;},get provisioned(){return provisioned;},advance:n=>{time+=n;}};
}
const secrets={bridgeKey:'b'.repeat(64),profileToken:'kody_at_SYNTHETIC_ONLY',cloudflareToken:'c'.repeat(40),account:'a'.repeat(32)};
test('actual lifecycle sequencing with synthetic provider: OFF provision, active receipt, OFF then delete',async()=>{
 const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);const receipt=await f.lifecycle.activate();
 assert.equal(receipt.kind,'exp710-activation-ready');assert.equal(receipt.caller,PILOT.caller);assert.equal(receipt.digest,PILOT.digest);assert.equal(receipt.deadline-receipt.checkedAt,600);assert.equal(f.enabled,true);
 await f.lifecycle.disable();const done=await f.lifecycle.cleanup();assert.equal(f.enabled,false);assert.equal(f.provisioned,false);assert.equal(done.tokenId,f.credential.id);assert.equal(f.state.phase,'cleaned');
 for(const [earlier,later]of[['introspect','provision'],['save:provision-attempted','provision'],['save:activation-attempted','deploy:true'],['deploy:false','remove'],['save:cleanup-attempted','remove']])assert.ok(f.events.indexOf(earlier)<f.events.indexOf(later));
});
test('no activation before provision, expired window, or replay of phase',async()=>{
 const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await assert.rejects(f.lifecycle.activate());await f.lifecycle.provisionSecrets(secrets);await assert.rejects(f.lifecycle.provisionSecrets(secrets));f.advance(301);await assert.rejects(f.lifecycle.activate());assert.equal(f.enabled,false);
});
test('ambiguous provisioning is reconciled read-only and cleaned without restart',async()=>{
 const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});f.lifecycle.provision=async()=>{throw new Error('AMBIGUOUS');};await assert.rejects(f.lifecycle.provisionSecrets(secrets));
 await f.lifecycle.disable();await f.lifecycle.cleanup();assert.equal(f.enabled,false);assert.ok(!f.events.some(x=>x.startsWith('restart:')||x.startsWith('deploy:')));
});
test('activation POST ambiguity triggers distinct OFF rollback, never a second activation POST',async()=>{
 const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);
 f.provider.restart=async phase=>{f.events.push('restart:'+phase);if(phase==='activate')throw new Error('AMBIGUOUS');};await assert.rejects(f.lifecycle.activate());await f.lifecycle.disable();await f.lifecycle.cleanup();
 assert.equal(f.events.filter(e=>e==='restart:activate').length,1);assert.equal(f.events.filter(e=>e==='restart:disable').length,1);assert.equal(f.enabled,false);
});
test('readiness retries only transient provider pending; permanent drift stops immediately',async()=>{
 const f=fixture();let calls=0;f.lifecycle.inspect=async()=>{calls++;throw new Error('DRIFT');};await assert.rejects(f.lifecycle.ready(true,{baseline:'x',activeWorker:'x'}));assert.equal(calls,1);
 calls=0;f.lifecycle.inspect=async()=>{calls++;if(calls===1)throw new ProviderPending();return {meta:{id:'x'}};};await f.lifecycle.ready(true,{baseline:'x',activeWorker:'x'});assert.equal(calls,2);
});

test('late readiness never emits an activation-ready receipt',async()=>{
 const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);
 const deploy=f.lifecycle.deploy;f.lifecycle.deploy=async(...args)=>{const version=await deploy(...args);f.advance(500);return version;};
 await assert.rejects(f.lifecycle.activate(),/Insufficient acceptance window/);assert.notEqual(f.state.phase,'active');
});

test('ambiguous activation publish never restarts; distinct verified OFF can still clean',async()=>{
 const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);
 const deploy=f.lifecycle.deploy;f.lifecycle.deploy=async(...args)=>{await deploy(...args);throw new Error('ACK_UNAVAILABLE');};
 await assert.rejects(f.lifecycle.activate(),/ACK_UNAVAILABLE/);assert.equal(f.state.phase,'activation-attempted');assert.ok(!f.events.some(e=>e.startsWith('restart:')));
 await assert.rejects(f.lifecycle.cleanup(),/verified OFF/);
 f.lifecycle.deploy=deploy;await f.lifecycle.disable();await f.lifecycle.cleanup();assert.equal(f.state.phase,'cleaned');assert.equal(f.events.filter(e=>e==='restart:activate').length,0);
});
test('ambiguous OFF publish cannot authorize restart or secret cleanup',async()=>{
 const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);await f.lifecycle.activate();
 const deploy=f.lifecycle.deploy;f.lifecycle.deploy=async(...args)=>{await deploy(...args);throw new Error('ACK_UNAVAILABLE');};
 await assert.rejects(f.lifecycle.disable(),/ACK_UNAVAILABLE/);await assert.rejects(f.lifecycle.cleanup(),/verified OFF/);
 assert.equal(f.state.phase,'disable-attempted');assert.ok(!f.events.includes('restart:disable'));assert.ok(!f.events.includes('remove'));
});

// Synthetic provider checks exercise the real orchestration, not live authority.
test('old and unrelated OFF Workers cannot allocate a new pilot state',async()=>{
 for(const id of ['7572d63f-a93e-4bb3-876a-bba6348cba7e','37d6aa2e-607f-442f-88b7-54e6c2c5e86c','00000000-0000-0000-0000-000000000000']){
  const f=fixture(),metadata=f.provider.metadata;f.provider.metadata=async()=>({...await metadata(),id});
  await assert.rejects(f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential}),/Initial OFF Worker differs/);
  assert.equal(f.state,undefined);assert.ok(!f.events.some(e=>e.startsWith('save:')||e.startsWith('deploy:')||e.startsWith('restart:')));
 }
});

test('provision failure reports precise safe stage before any CF write',async()=>{
 const f=fixture(),stages=[];f.lifecycle.reportProvision=(stage,status)=>stages.push({stage,status});
 await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});f.lifecycle.introspect=async()=>{throw new Error('PRIVATE_DATA');};
 await assert.rejects(f.lifecycle.provisionSecrets(secrets));assert.deepEqual(stages.at(-1),{stage:'candidate-introspection',status:'failed'});assert.equal(f.state.phase,'preflight');assert.ok(!f.events.includes('provision'));assert.ok(!JSON.stringify(stages).includes('PRIVATE_DATA'));
});
test('lease expiring during introspection cannot persist attempt or transfer bindings',async()=>{
 const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});
 f.lifecycle.introspect=async(_token,o)=>{f.advance(600);return o.expected;};
 await assert.rejects(f.lifecycle.provisionSecrets(secrets),/Pilot lease expired/);assert.equal(f.state.phase,'preflight');assert.ok(!f.events.includes('provision'));
});
