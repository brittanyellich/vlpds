// Lifecycle orchestration is separate from transport so tests exercise actual
// sequencing and rollback decisions without any real provider or credential.
import {PILOT,activationPlan,transferSecrets} from './pilot-activation-plan.mjs';
import {checkBindings,ProviderPending} from './pilot-provider.mjs';
import {transitionReason} from './pilot-transition-diagnostic.mjs';
export class PilotLifecycle {
 constructor({provider,save,load,deploy,provision,introspect,remove,card,now,sleep,identity,reportProvision=()=>{},reportActivation=()=>{},reportOff=()=>{}}) {
  Object.assign(this,{provider,save,load,deploy,provision,introspect,remove,card,now,sleep,identity,reportProvision,reportActivation,reportOff});
 }
 async inspect(enabled,provisioned,baseline,deadline,mark=()=>{}) {
  const checkedAt=this.now();mark('runtime-status');await this.provider.status();mark('card-authority');await this.provider.currentCardKey();
  mark('worker-metadata');const meta=await this.provider.metadata();mark('worker-bindings');const ordinaryHash=checkBindings(meta,{enabled,baseline,provisioned,card:this.card,deadline});
  mark('public-checks');const card=await this.provider.publicChecks(enabled);
  if(enabled && !this.sameCard(card.bytes,this.card))throw new Error('Served Card mismatch');
  mark('runtime-status-final');await this.provider.status();if(this.now()-checkedAt>30)throw new Error('Stale pilot checks');
  return {meta,ordinaryHash,checkedAt};
 }
 sameCard(bytes,card) {try {const normalize=v=>Array.isArray(v)?v.map(normalize):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,normalize(v[k])])):v;
  return JSON.stringify(normalize(JSON.parse(bytes)))===JSON.stringify(normalize(JSON.parse(card)));}catch{return false;}}
 async preflight({account,credential}) {
  const {meta,ordinaryHash,checkedAt}=await this.inspect(false,false);
  if(meta.id!==PILOT.offWorker)throw new Error('Initial OFF Worker differs');
  const plan=activationPlan({account,now:this.now(),credential,evidence:{checkedAt,desired:this.provider.image,current:this.provider.image,running:true,
    runtime:'native-profile-v1',revision:PILOT.revision,platform:'linux/amd64',workerVersion:meta.id,enabled:false,agentSecretBindings:0,
    publicChecks:{health:200,ui:200,card:404},cardCurrentKey:PILOT.cardKey,cardSignatureVerified:true,cardSha256:PILOT.cardHash}});
  // Hash+current key bind exact previously crypto-verified local Card artifact.
  // Runner separately hashes actual bytes; this planner receipt is not a verifier.
  if(!credential || credential.maxExpiresAt-this.now()<900)throw new Error('Acceptance window unavailable');
  const state={version:1,phase:'preflight',baseline:ordinaryHash,offScriptEtag:meta.scriptEtag,credential,deadline:this.now()+600,...this.identity};
  await this.save(state);return plan;
 }
 async provisionSecrets(secrets) {
  const step=async(stage,run)=>{this.reportProvision(stage,'started');try{const result=await run();this.reportProvision(stage,'passed');return result;}catch(error){this.reportProvision(stage,'failed',error);throw error;}};
  const s=await step('load-private-state',()=>this.load());
  await step('phase-and-lease',()=>{if(s.phase!=='preflight'||this.now()>=s.deadline)throw new Error('Pilot phase refused');});
  await step('fresh-off-state',()=>this.inspect(false,false,s.baseline));
  const candidate=secrets.profileToken;
  s.credential=await step('candidate-introspection',()=>{
   if(typeof this.introspect!=='function')throw new Error('Candidate introspection required');
   return this.introspect(candidate,{expected:s.credential,deadline:s.deadline,now:this.now()});
  });
  await step('persist-provision-attempt',async()=>{
   if(this.now()>=s.deadline)throw new Error('Pilot lease expired');
   s.phase='provision-attempted';await this.save(s); // Persist before any mutation.
  });
  await step('transfer-two-bindings',()=>transferSecrets({...secrets,profileToken:candidate},this.provision));
  const {meta}=await step('verify-provisioned-off',async()=>{const result=await this.inspect(false,true,s.baseline);if(result.meta.scriptEtag!==s.offScriptEtag)throw new Error('Provision changed script');return result;});
  await step('persist-provisioned-state',async()=>{s.provisionWorker=meta.id;s.provisioned=true;s.phase='provisioned';await this.save(s);});
 }

 async transitionStep(enabled,stage,run) {
  const report=enabled?this.reportActivation:this.reportOff;report(stage,'started');
  try{const result=await run();report(stage,'passed');return result;}catch(error){report(stage,'failed',{reason:transitionReason(error)});throw error;}
 }
 async activate() {
  const step=(stage,run)=>this.transitionStep(true,stage,run);
  const s=await step('load-state',()=>this.load());
  await step('phase-lease',()=>{if(s.phase!=='provisioned'||s.deadline-this.now()<300)throw new Error('Pilot phase refused');});
  await step('fresh-off-state',async()=>{const before=await this.inspect(false,true,s.baseline);if(before.meta.id!==s.provisionWorker||before.meta.scriptEtag!==s.offScriptEtag)throw new Error('Worker changed');});
  await step('save-attempt',async()=>{s.phase='activation-attempted';await this.save(s);});
  const deployedVersion=await step('publish-ack',()=>this.deploy(true,s.deadline));
  const meta=await step('worker-config',async()=>{const m=await this.provider.metadata();if(m.id!==deployedVersion)throw new Error('Published Worker mismatch');checkBindings(m,{enabled:true,provisioned:true,baseline:s.baseline,card:this.card,deadline:s.deadline});return m;});
  await step('save-worker',async()=>{s.activeWorker=meta.id;await this.save(s);});
  await step('runtime-restart',()=>this.provider.restart('activate'));
  await step('readiness',()=>this.ready(true,s));
  await step('persist-active',async()=>{if(s.deadline-this.now()<120)throw new Error('Insufficient acceptance window');s.phase='active';await this.save(s);});
  return {version:1,kind:'exp710-activation-ready',...this.identity,digest:PILOT.digest,workerVersion:s.activeWorker,
    caller:PILOT.caller,recipient:'did:plc:6tlvgafuonoighfrtpejff5m',profile:PILOT.profile,artifactRevision:PILOT.revision,cardKey:PILOT.cardKey,cardArtifactSha256:PILOT.cardHash,
    checkedAt:this.now(),deadline:s.deadline,cardPayloadSha256:'0239e2b2eb803c6865f8f7f62203da37eeba64f11ceea25a05a54735d866bf43'};
 }
 async ready(enabled,s) {
  const report=enabled?this.reportActivation:this.reportOff;
  for(let i=0;i<20;i++){let check='not-started';try{const r=await this.inspect(enabled,true,s.baseline,s.deadline,value=>{check=value;});
    if(enabled&&r.meta.id!==s.activeWorker)throw new Error('Active Worker differs');report('readiness-poll','passed',{attempt:i+1,check,reason:'none'});return;
   }catch(e){const retry=e instanceof ProviderPending&&i<19;report('readiness-poll',retry?'pending':'failed',{attempt:i+1,check,reason:transitionReason(e)});if(!retry)throw new Error('Pilot readiness failed');await this.sleep(3000);}}
 }
 async disable() {
  const step=(stage,run)=>this.transitionStep(false,stage,run);
  const s=await step('load-state',()=>this.load());if(['cleaned','disabled'].includes(s.phase))return;
  if(['provision-attempted','provisioned'].includes(s.phase)) {
   await step('reconcile-provisioned-off',async()=>{
    await this.provider.status();const meta=await this.provider.metadata();
    const count=meta.bindings.filter(b=>['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'].includes(b.name)).length;
    if(![0,2].includes(count))throw new Error('Partial pilot bindings; reconcile');
    checkBindings(meta,{enabled:false,provisioned:count===2,baseline:s.baseline,card:this.card,deadline:s.deadline});
    await this.provider.publicChecks(false);s.provisioned=count===2;
   });
   await step('persist-disabled',async()=>{s.phase='disabled';await this.save(s);});return;
  }
  // Distinct OFF rollback after ambiguous activation; never replay activation.
  await step('save-attempt',async()=>{s.phase='disable-attempted';await this.save(s);});
  const deployedVersion=await step('publish-ack',()=>this.deploy(false));
  const meta=await step('worker-config',async()=>{const m=await this.provider.metadata();if(m.id!==deployedVersion)throw new Error('OFF Worker mismatch');checkBindings(m,{enabled:false,provisioned:true,baseline:s.baseline,card:this.card,deadline:s.deadline});return m;});
  await step('runtime-restart',()=>this.provider.restart('disable'));
  await step('readiness',()=>this.ready(false,s));
  await step('persist-disabled',async()=>{s.phase='disabled';s.offWorker=meta.id;await this.save(s);});
 }

 async cleanup() {
  const s=await this.load();if(s.phase!=='disabled')throw new Error('Cleanup requires verified OFF');
  await this.inspect(false,s.provisioned!==false,s.baseline);s.phase='cleanup-attempted';await this.save(s);if(s.provisioned!==false)await this.remove();
  await this.inspect(false,false,s.baseline);s.phase='cleaned';await this.save(s);
  return {kind:'exp710-off-cleaned',...this.identity,digest:PILOT.digest,tokenId:s.credential.id,revocation:'custodian-confirmation-required'};
 }
}
