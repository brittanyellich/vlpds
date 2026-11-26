import test from 'node:test';import assert from 'node:assert/strict';
import{PilotLifecycle}from'../scripts/pilot-lifecycle.mjs';import{PILOT}from'../scripts/pilot-activation-plan.mjs';import{ProviderPending,CardPending}from'../scripts/pilot-provider.mjs';
function fixture({ownerConsentRequired=false}={}){
 let state,enabled=false,consentBinding=false,provisioned=false,version=PILOT.offWorker,time=1800000000;const events=[];
 const card='{"synthetic":true}',identity={repository:'brittanyellich/vlpds',runId:123,head:'a'.repeat(40)};
 const metadata=()=>({id:version,scriptEtag:'e'.repeat(64),bindings:[{name:'PUBLIC_HOST',type:'plain_text',text:'pds.crate.social'},
 ...Object.entries({AGENT_A2A_ENABLED:enabled?'true':'false',AGENT_A2A_RUNTIME:'native-profile-v1',...(consentBinding?{AGENT_A2A_REQUIRE_OWNER_CONSENT:'true'}:{}),...(enabled?{AGENT_A2A_EXPIRES_AT:String(state?.deadline),AGENT_A2A_CALLER_DID:PILOT.caller,AGENT_A2A_CAPACITY:'1000',AGENT_A2A_SIGNED_CARD_JSON:card,AGENT_A2A_CARD_KEY_MULTIBASE:PILOT.cardKey}:{})}).map(([name,text])=>({name,text,type:'plain_text'})),
 ...(provisioned?['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'].map(name=>({name,type:'secret_text'})):[])]});
 const provider={image:`registry.cloudflare.com/${'a'.repeat(32)}/vlpds@${PILOT.digest}`,status:async()=>{events.push('status');},currentCardKey:async()=>PILOT.cardKey,metadata:async()=>metadata(),publicChecks:async e=>{assert.equal(e,enabled);return {bytes:Buffer.from(card)};},restart:async phase=>{events.push('restart:'+phase);}};
 const lifecycle=new PilotLifecycle({ownerConsentRequired,provider,save:async s=>{state=structuredClone(s);events.push('save:'+s.phase);},load:async()=>structuredClone(state),deploy:async (e,_deadline,policy)=>{events.push('deploy:'+e);enabled=e;consentBinding=e&&policy?.ownerConsentRequired===true;version=e?'a'.repeat(36):'b'.repeat(36);return version;},
 introspect:async(token,o)=>{assert.equal(token,'kody_at_SYNTHETIC_ONLY');events.push('introspect');return o.expected;},provision:async x=>{assert.ok(x.stdin.includes('SYNTHETIC'));events.push('provision');provisioned=true;version='c'.repeat(36);return true;},remove:async()=>{events.push('remove');provisioned=false;},card,now:()=>time,sleep:async ms=>{time+=ms/1000;},identity});
 const credential={id:'synthetic_opaque_id',idleSeconds:900,maxSeconds:3600,orgBinding:'org',profileId:PILOT.profile,scopes:['org:execute'],issuedAt:time,expiresAt:time+900,maxExpiresAt:time+3600};
 return {lifecycle,provider,events,credential,get state(){return state;},get enabled(){return enabled;},get consentBinding(){return consentBinding;},get provisioned(){return provisioned;},advance:n=>{time+=n;}};
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
 for(const id of ['df75d444-fd52-4314-b686-6461b792f4b4','7572d63f-a93e-4bb3-876a-bba6348cba7e','37d6aa2e-607f-442f-88b7-54e6c2c5e86c','00000000-0000-0000-0000-000000000000']){
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

test('restart timeout is localized and never retried; distinct OFF still required',async()=>{
 const {transitionDiagnostic}=await import('../scripts/pilot-transition-diagnostic.mjs');const f=fixture();let trace,t=0;
 await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);
 f.lifecycle.reportActivation=transitionDiagnostic('activate',{...f.lifecycle.identity,workerQualificationSha256:'b'.repeat(64)},s=>trace=JSON.parse(s),()=>t);
 const restart=f.provider.restart;f.provider.restart=async phase=>{if(phase==='activate'){f.events.push('restart:activate');t+=75000;throw new ProviderPending('Provider unavailable');}return restart(phase);};
 await assert.rejects(f.lifecycle.activate());assert.equal(trace.steps.at(-1).stage,'runtime-restart');assert.equal(trace.steps.at(-1).durationMs,75000);assert.equal(trace.steps.at(-1).reason,'request-unavailable');assert.equal(trace.polls.length,0);assert.equal(f.events.filter(e=>e==='restart:activate').length,1);assert.notEqual(f.state.phase,'active');
 await f.lifecycle.disable();await f.lifecycle.cleanup();assert.equal(f.state.phase,'cleaned');
});
test('twenty pending Card checks are localized as readiness failure without extra restart',async()=>{
 const {transitionDiagnostic}=await import('../scripts/pilot-transition-diagnostic.mjs');const f=fixture();let trace;
 await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);
 f.lifecycle.reportActivation=transitionDiagnostic('activate',{...f.lifecycle.identity,workerQualificationSha256:'b'.repeat(64)},s=>trace=JSON.parse(s),()=>f.lifecycle.now()*1000);
 const checks=f.provider.publicChecks;f.provider.publicChecks=async enabled=>{if(enabled)throw new CardPending(503,Buffer.from('{"error":"Signed Card trust unavailable"}'),'application/json');return checks(enabled);};
 await assert.rejects(f.lifecycle.activate(),/Pilot readiness failed/);assert.equal(trace.steps.at(-1).stage,'readiness');assert.equal(trace.polls.length,20);assert.ok(trace.polls.every(p=>p.check==='public-checks'&&p.reason==='card-http-503-trust-unavailable'));assert.equal(trace.polls.at(-1).status,'failed');assert.equal(trace.steps.at(-1).durationMs,57000);assert.equal(f.events.filter(e=>e==='restart:activate').length,1);assert.notEqual(f.state.phase,'active');
 await f.lifecycle.disable();await f.lifecycle.cleanup();assert.equal(f.state.phase,'cleaned');
});
test('publish failure and applied Worker mismatch are separate boundaries before restart',async()=>{
 for(const scenario of ['publish','worker']){
  const f=fixture(),stages=[];await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);f.lifecycle.reportActivation=(stage,status)=>stages.push({stage,status});
  if(scenario==='publish')f.lifecycle.deploy=async()=>{throw new Error('PRIVATE_DATA');};else{const metadata=f.provider.metadata;f.provider.metadata=async()=>({...await metadata(),...(f.enabled?{id:'wrong'}:{})});}
  await assert.rejects(f.lifecycle.activate());assert.equal(stages.at(-1).stage,scenario==='publish'?'publish-ack':'worker-config');assert.equal(stages.at(-1).status,'failed');assert.ok(!f.events.some(e=>e.startsWith('restart:')));assert.ok(!JSON.stringify(stages).includes('PRIVATE_DATA'));
 }
});
test('OFF restart failure is observable and cannot authorize binding cleanup',async()=>{
 const f=fixture(),stages=[];await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);await f.lifecycle.activate();f.lifecycle.reportOff=(stage,status)=>stages.push({stage,status});
 const restart=f.provider.restart;f.provider.restart=async phase=>{if(phase==='disable')throw new ProviderPending('Provider unavailable');return restart(phase);};
 await assert.rejects(f.lifecycle.disable());assert.deepEqual(stages.at(-1),{stage:'runtime-restart',status:'failed'});await assert.rejects(f.lifecycle.cleanup(),/verified OFF/);assert.ok(!f.events.includes('remove'));
});
test('diagnostic disk failure does not prevent verified OFF and cleanup',async()=>{
 const {bestEffortTransition}=await import('../scripts/pilot-transition-diagnostic.mjs');const f=fixture();
 await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);await f.lifecycle.activate();
 f.lifecycle.reportOff=bestEffortTransition(()=>{throw new Error('DISK_FULL');});await f.lifecycle.disable();await f.lifecycle.cleanup();assert.equal(f.enabled,false);assert.equal(f.state.phase,'cleaned');
});
test('diagnostic initialization failure cannot prevent OFF and cleanup',async()=>{
 const {createTransitionReporter}=await import('../scripts/pilot-transition-diagnostic.mjs');const f=fixture();
 await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);await f.lifecycle.activate();
 f.lifecycle.reportOff=createTransitionReporter('disable',{runId:0},()=>{});await f.lifecycle.disable();await f.lifecycle.cleanup();assert.equal(f.enabled,false);assert.equal(f.state.phase,'cleaned');
});


test('explicit required-consent mode adds exact active binding then removes it before OFF cleanup',async()=>{
 const f=fixture({ownerConsentRequired:true});
 await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});
 assert.equal(f.state.ownerConsentRequired,true);assert.equal(f.consentBinding,false);
 await f.lifecycle.provisionSecrets(secrets);const ready=await f.lifecycle.activate();
 assert.equal(ready.ownerConsentRequired,true);assert.equal(f.consentBinding,true);
 await f.lifecycle.disable();assert.equal(f.consentBinding,false);
 await f.lifecycle.cleanup();assert.equal(f.state.phase,'cleaned');assert.equal(f.provisioned,false);
 assert.ok(f.events.indexOf('deploy:false')<f.events.indexOf('remove'));
});
test('saved required-consent mode cannot resume activation as legacy, but distinct OFF remains possible',async()=>{
 const f=fixture({ownerConsentRequired:true});await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});
 await f.lifecycle.provisionSecrets(secrets);f.lifecycle.ownerConsentRequired=false;
 await assert.rejects(f.lifecycle.activate(),/consent mode differs/);
 assert.ok(!f.events.includes('deploy:true'));await f.lifecycle.disable();await f.lifecycle.cleanup();assert.equal(f.state.phase,'cleaned');
});
test('missing required binding refuses activation before restart; OFF rollback restores baseline',async()=>{
 const f=fixture({ownerConsentRequired:true});await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);
 const deploy=f.lifecycle.deploy;f.lifecycle.deploy=(e,deadline)=>deploy(e,deadline,{ownerConsentRequired:false});
 await assert.rejects(f.lifecycle.activate());assert.ok(!f.events.includes('restart:activate'));
 await f.lifecycle.disable();await f.lifecycle.cleanup();assert.equal(f.state.phase,'cleaned');
});
test('OFF binding residue blocks restart and secret cleanup',async()=>{
 const f=fixture({ownerConsentRequired:true});await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);await f.lifecycle.activate();
 const metadata=f.provider.metadata;f.provider.metadata=async()=>{const m=await metadata();if(!f.enabled)m.bindings.push({name:'AGENT_A2A_REQUIRE_OWNER_CONSENT',type:'plain_text',text:'true'});return m;};
 await assert.rejects(f.lifecycle.disable());assert.ok(!f.events.includes('restart:disable'));
 await assert.rejects(f.lifecycle.cleanup());assert.ok(!f.events.includes('remove'));
});

test('invalid configured or saved consent modes fail closed',async()=>{
 for(const ownerConsentRequired of ['true',null,1])assert.throws(()=>fixture({ownerConsentRequired}),/Explicit consent mode/);
 for(const invalid of ['true',null,1]){
  const f=fixture();await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});f.state.ownerConsentRequired=invalid;
  await assert.rejects(f.lifecycle.provisionSecrets(secrets),/consent mode differs/);
  await assert.rejects(f.lifecycle.disable(),/consent mode differs/);
  assert.ok(!f.events.includes('provision'));
 }
});

test('selector drift after activation still allows distinct OFF while preserving saved required policy',async()=>{
 const f=fixture({ownerConsentRequired:true});await f.lifecycle.preflight({account:'a'.repeat(32),credential:f.credential});await f.lifecycle.provisionSecrets(secrets);await f.lifecycle.activate();
 f.lifecycle.ownerConsentRequired=false;await assert.rejects(f.lifecycle.activate(),/consent mode differs/);
 await f.lifecycle.disable();await f.lifecycle.cleanup();
 assert.equal(f.state.ownerConsentRequired,true);assert.equal(f.consentBinding,false);assert.equal(f.state.phase,'cleaned');
 assert.equal(f.events.filter(e=>e==='deploy:true').length,1);assert.equal(f.events.filter(e=>e==='deploy:false').length,1);
});
