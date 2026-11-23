// Fixture-only observer -> reviewed consumer copy -> inert private Terminal.
import{mkdtemp,chmod,rm,writeFile,lstat}from'node:fs/promises';
import{createHash}from'node:crypto';
import{childBytes,watchReceipt}from'./rollout-observer.mjs';
import{claimRun,rehearseConsumerFixture,verifiedLauncherPlan}from'./rollout-terminal.mjs';
import{PILOT}from'../../deploy/cloudflare/scripts/pilot-activation-plan.mjs';
export async function integratedFixture({source,python,pins,fixturePins,claimDirectory,identity,scenario='delay54',terminalApp=false}){
 const allowed=['delay54','stale','missing','wrong-run','invalid-signature','unlock-timeout','request-timeout','short-lease','cleanup-failure','age120','age121','lease180','lease179'];
 if(!allowed.includes(scenario))throw Error('Fixture scenario refused');
 const directory=await mkdtemp('/private/tmp/exp710-integrated-');await chmod(directory,0o700);const timing=[];let phase='qualification';let launcherPlanVerified=false;
 const timed=async(name,fn)=>{phase=name;const start=performance.now();try{return await fn();}finally{timing.push({phase:name,milliseconds:performance.now()-start});}};
 try{
  await timed('pinned-launch-plan',()=>verifiedLauncherPlan({source,python,pins,identity,output:directory+'/never-live.json'}));launcherPlanVerified=true;
  phase='claim';
  if(!await claimRun(claimDirectory,identity))return {rehearsal:true,result:'duplicate-refused',liveRequests:0,timing};
  const receipt={version:1,kind:'exp710-activation-ready',workerQualificationSha256:'253b25c2baa4983042d803787b60ec0be9838c253b4860761257d0795b345e36',repository:'brittanyellich/vlpds',runId:identity.runId,head:identity.head,digest:PILOT.digest,workerVersion:'12345678-1234-1234-1234-123456789abc',caller:PILOT.caller,recipient:'did:plc:6tlvgafuonoighfrtpejff5m',profile:PILOT.profile,artifactRevision:PILOT.revision,cardKey:PILOT.cardKey,cardArtifactSha256:PILOT.cardHash,cardPayloadSha256:'0239e2b2eb803c6865f8f7f62203da37eeba64f11ceea25a05a54735d866bf43',checkedAt:1000,deadline:scenario==='short-lease'?1200:scenario==='lease180'?1234:scenario==='lease179'?1233:1583};
  const zip=await childBytes('python3',['-c',"import sys,io,zipfile; b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('exp710-activation-ready.json',sys.stdin.buffer.read()); z.close(); sys.stdout.buffer.write(b.getvalue())"],{input:Buffer.from(JSON.stringify(receipt))});
  const run={id:identity.runId,repository:{full_name:'brittanyellich/vlpds'},head_sha:identity.head,head_branch:'main',run_attempt:1,event:'workflow_dispatch',path:'.github/workflows/cloudflare-agent-pilot.yml',status:'in_progress',conclusion:null};
  const jobs={total_count:1,jobs:[{name:'pilot',run_id:identity.runId,head_sha:identity.head,steps:['Activate guarded Otto-only pilot','Publish sanitized activation-ready receipt'].map(name=>({name,status:'completed',conclusion:'success'}))}]};
  const artifacts={total_count:1,artifacts:[{id:42,name:`exp710-activation-ready-${identity.runId}`,workflow_run:{id:identity.runId,head_sha:identity.head},expired:false,size_in_bytes:zip.length,digest:'sha256:'+createHash('sha256').update(zip).digest('hex')}]};
  if(scenario==='missing'){artifacts.total_count=0;artifacts.artifacts=[];}
  if(scenario==='wrong-run')run.id++;
  const api={get:async path=>path.endsWith('/zip')?zip:Buffer.from(JSON.stringify(path.includes('/jobs?')?jobs:path.includes('/artifacts?')?artifacts:run))};
  await timed('fixture-observer',()=>watchReceipt(api,identity,{intervalMs:1,maxWaitMs:scenario==='missing'?10:1000}));
  const bundle={rehearsalOnly:true,run,jobs,artifacts,zip:zip.toString('base64'),checkedAt:1000,deadline:receipt.deadline,now:['stale','age121'].includes(scenario)?1121:scenario==='age120'?1120:1054,unlockSeconds:scenario==='unlock-timeout'?61:['age120','lease180','lease179'].includes(scenario)?0:10,requestSeconds:scenario==='request-timeout'?11:['age120','lease180','lease179'].includes(scenario)?0:2,case:scenario};
  const tty=await timed('policy-consumer-private-terminal',()=>rehearseConsumerFixture(directory,{source,python,pins,fixturePins,bundle,terminalApp}));
  let cleanupVerified=false,cleanupAttempted=false;
  const resource=directory+'/synthetic-lease.json';await writeFile(resource,JSON.stringify({enabled:true,lease:true}),{mode:0o600,flag:'wx'});
  try{await timed('synthetic-cleanup',async()=>{
   cleanupAttempted=true;if(scenario==='cleanup-failure')throw Error('Injected synthetic cleanup failure');
   await rm(resource);try{await lstat(resource);throw Error('Synthetic resource retained');}catch(error){if(error.code!=='ENOENT')throw error;}
   cleanupVerified=true;
  });}catch{/* failure never becomes accepted completion; owned files still removed below */}
  return {rehearsal:true,result:tty.acceptedSynthetic&&cleanupVerified?'synthetic-complete':'refused',liveRequests:0,realPrompt:false,liveExecutionEnabled:false,launcherPlanVerified,proposedOffWorker:PILOT.offWorker,tty,syntheticCleanupVerified:cleanupVerified,cleanupAttempted,timing};
 }catch{return{rehearsal:true,result:'refused',failedPhase:phase,liveRequests:0,realPrompt:false,timing};}
 finally{await rm(directory,{recursive:true,force:true});}
}
