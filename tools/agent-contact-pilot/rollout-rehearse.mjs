import{privateTemporaryDirectory}from'./rollout-private-temp.mjs';
// Single-process read-only observer -> pinned launch plan -> inert private TTY.
// Archive rehearsal cannot pass live freshness, prompt, authenticate or send HTTP.
import{mkdtemp,chmod,rm}from'node:fs/promises';
import{github,watchReceipt}from'./rollout-observer.mjs';
import{claimRun,verifiedLauncherPlan,rehearseTerminal}from'./rollout-terminal.mjs';
export async function rehearseObservedRun({identity,source,python,pins,claimDirectory,terminalApp=false,api=github(identity.runId,identity.head)}){
 const directory=await privateTemporaryDirectory('exp710-observer-rehearsal-');await chmod(directory,0o700);const timing=[];
 const phase=async(name,fn)=>{const started=performance.now();try{return await fn();}finally{timing.push({phase:name,milliseconds:performance.now()-started});}};
 try{
  if(!await claimRun(claimDirectory,identity))throw Error('Duplicate rehearsal');
  const proof=await phase('authenticated-github-archive',()=>watchReceipt(api,identity,{archive:true,maxWaitMs:180000}));
  const plan=await phase('pinned-launch-plan',()=>verifiedLauncherPlan({source,python,pins,identity,output:directory+'/acceptance.json'}));
  const tty=await phase('inert-private-terminal',()=>rehearseTerminal(directory,{terminalApp}));
  return {result:'REHEARSAL_ONLY',liveRequests:0,prompted:false,artifactId:proof.artifactId,artifactDigest:proof.artifactDigest,proofAgeSeconds:Math.floor(Date.now()/1000)-proof.checkedAt,liveFreshnessAccepted:false,launcherPlanVerified:plan.liveExecutionEnabled===false,tty,timing,temporaryFilesRemovedAfterReturn:true};
 }finally{await rm(directory,{recursive:true,force:true});}
}

// Rollout-owned integration entry. Its only execution adapter is the inert
// fixture snapshot; no live CLI, credential or request adapter is accepted.
export async function rehearseRolloutLaunch(options){
 const {PILOT}=await import('../../deploy/cloudflare/scripts/pilot-activation-plan.mjs');
 if(options.mode!=='fixture-only'||options.approvedHead!==options.identity?.head||
    options.baselineWorker!==PILOT.offWorker||options.liveExecutionEnabled!==false)
  throw Error('Rehearsal qualification refused');
 const {integratedFixture}=await import('./rollout-integrated-fixture.mjs');
 return integratedFixture(options);
}
