// Lifecycle orchestration is separate from transport so tests exercise actual
// sequencing and rollback decisions without any real provider or credential.
import {PILOT,activationPlan,transferSecrets} from './pilot-activation-plan.mjs';
import {checkBindings,ProviderPending} from './pilot-provider.mjs';
export class PilotLifecycle {
 constructor({provider,save,load,deploy,provision,introspect,remove,card,now,sleep,identity}) {
  Object.assign(this,{provider,save,load,deploy,provision,introspect,remove,card,now,sleep,identity});
 }
 async inspect(enabled,provisioned,baseline,deadline) {
  const checkedAt=this.now();await this.provider.status();await this.provider.currentCardKey();
  const meta=await this.provider.metadata();const ordinaryHash=checkBindings(meta,{enabled,baseline,provisioned,card:this.card,deadline});
  const card=await this.provider.publicChecks(enabled);
  if(enabled && !this.sameCard(card.bytes,this.card))throw new Error('Served Card mismatch');
  await this.provider.status();if(this.now()-checkedAt>30)throw new Error('Stale pilot checks');
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
  const s=await this.load();if(s.phase!=='preflight' || this.now()>=s.deadline)throw new Error('Pilot phase refused');
  await this.inspect(false,false,s.baseline);
  if(typeof this.introspect!=='function')throw new Error('Candidate introspection required');
  const candidate=secrets.profileToken;
  s.credential=await this.introspect(candidate,{expected:s.credential,deadline:s.deadline,now:this.now()});
  s.phase='provision-attempted';await this.save(s); // Persist before any mutation.
  await transferSecrets({...secrets,profileToken:candidate},this.provision);
  const {meta}=await this.inspect(false,true,s.baseline);if(meta.scriptEtag!==s.offScriptEtag)throw new Error('Provision changed script');s.provisionWorker=meta.id;s.provisioned=true;s.phase='provisioned';await this.save(s);
 }
 async activate() {
  const s=await this.load();if(s.phase!=='provisioned' || s.deadline-this.now()<300)throw new Error('Pilot phase refused');
  const before=await this.inspect(false,true,s.baseline);if(before.meta.id!==s.provisionWorker || before.meta.scriptEtag!==s.offScriptEtag)throw new Error('Worker changed');
  s.phase='activation-attempted';await this.save(s);const deployedVersion=await this.deploy(true,s.deadline);
  // Edge metadata must be right before changing process configuration. The old
  // process can still return Card404 until the deliberate restart.
  const meta=await this.provider.metadata();if(meta.id!==deployedVersion)throw new Error('Published Worker mismatch');checkBindings(meta,{enabled:true,provisioned:true,baseline:s.baseline,card:this.card,deadline:s.deadline});
  s.activeWorker=meta.id;await this.save(s);await this.provider.restart('activate');
  await this.ready(true,s);if(s.deadline-this.now()<120)throw new Error('Insufficient acceptance window');s.phase='active';await this.save(s);
  return {version:1,kind:'exp710-activation-ready',...this.identity,digest:PILOT.digest,workerVersion:s.activeWorker,
    caller:PILOT.caller,recipient:'did:plc:6tlvgafuonoighfrtpejff5m',profile:PILOT.profile,artifactRevision:PILOT.revision,cardKey:PILOT.cardKey,cardArtifactSha256:PILOT.cardHash,
    checkedAt:this.now(),deadline:s.deadline,cardPayloadSha256:'0239e2b2eb803c6865f8f7f62203da37eeba64f11ceea25a05a54735d866bf43'};
 }
 async ready(enabled,s) {
  for(let i=0;i<20;i++){try{const r=await this.inspect(enabled,true,s.baseline,s.deadline);
    if(enabled && r.meta.id!==s.activeWorker)throw new Error('Active Worker differs');return;
   }catch(e){if(!(e instanceof ProviderPending) || i===19)throw new Error('Pilot readiness failed');await this.sleep(3000);}}
 }
 async disable() {
  const s=await this.load();if(['cleaned','disabled'].includes(s.phase))return;
  if(['provision-attempted','provisioned'].includes(s.phase)) {
   // Provisioning cannot enable routes. Reconcile a lost API acknowledgment by
   // readback only; do not resend secrets or restart an already-OFF process.
   await this.provider.status();const meta=await this.provider.metadata();
   const count=meta.bindings.filter(b=>['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'].includes(b.name)).length;
   if(![0,2].includes(count))throw new Error('Partial pilot bindings; reconcile');
   checkBindings(meta,{enabled:false,provisioned:count===2,baseline:s.baseline,card:this.card,deadline:s.deadline});
   await this.provider.publicChecks(false);s.provisioned=count===2;s.phase='disabled';await this.save(s);return;
  }
  // Closing public edge is allowed even after ambiguous activation. This is a
  // distinct rollback, never a replay of the activation POST.
  s.phase='disable-attempted';await this.save(s);const deployedVersion=await this.deploy(false);
  const meta=await this.provider.metadata();if(meta.id!==deployedVersion)throw new Error('OFF Worker mismatch');checkBindings(meta,{enabled:false,provisioned:true,baseline:s.baseline,card:this.card,deadline:s.deadline});
  await this.provider.restart('disable');await this.ready(false,s);
  s.phase='disabled';s.offWorker=meta.id;await this.save(s);
 }
 async cleanup() {
  const s=await this.load();if(s.phase!=='disabled')throw new Error('Cleanup requires verified OFF');
  await this.inspect(false,s.provisioned!==false,s.baseline);s.phase='cleanup-attempted';await this.save(s);if(s.provisioned!==false)await this.remove();
  await this.inspect(false,false,s.baseline);s.phase='cleaned';await this.save(s);
  return {kind:'exp710-off-cleaned',...this.identity,digest:PILOT.digest,tokenId:s.credential.id,revocation:'custodian-confirmation-required'};
 }
}
