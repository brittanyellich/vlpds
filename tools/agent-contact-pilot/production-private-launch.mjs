// Operator-only library. No CLI, route, automatic dispatch or enable-on-import.
import qualification from './proposals/rollout-qualification.json' with {type:'json'};
import{readFile,writeFile,mkdir,rm}from'node:fs/promises';import{join}from'node:path';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';
import{github,watchReceipt}from'./rollout-observer.mjs';import{claimRun,verifiedLauncherPlan}from'./rollout-terminal.mjs';
import{executeOwnedPrivateCli,requireExecutionWindow}from'./owned-private-cli.mjs';import{privateTemporaryDirectory}from'./rollout-private-temp.mjs';import{PILOT}from'../../deploy/cloudflare/scripts/pilot-activation-plan.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
export function requireProductionGrant(grant,identity){
 if(!identity||!Number.isSafeInteger(identity.runId)||identity.runId<1||!/^[a-f0-9]{40}$/.test(identity.head??'')||
 grant?.kind!=='one-bounded-hosted-otto'||grant.approved!==true||grant.runId!==identity.runId||grant.head!==identity.head||
 grant.baselineWorker!==PILOT.offWorker||grant.leaseSeconds!==600||!Number.isSafeInteger(grant.preflightRunId)||grant.preflightRunId<1||grant.preflightRunId===identity.runId||grant.preflightHead!==identity.head||grant.preflightVerified!==true||
 grant.productionExecutionQualified!==true||grant.custodianAvailable!==true||grant.operatorAvailable!==true)
  throw Error('Exact private production grant required');
}
async function observeAndExecute({identity,source,python,pins,initSha256,output,claimDirectory,api,signal,onReady,unlockMs},denyNetwork){
 await verifiedLauncherPlan({source,python,pins,identity,output});
 if(!await claimRun(claimDirectory,identity))throw Error('Duplicate private production launch refused');
 const proof=await watchReceipt(api,identity,{signal,archive:false,maxWaitMs:180000});requireExecutionWindow(proof);
 return executeOwnedPrivateCli({source,python,pins,initSha256,interpreterSha256:qualification.fixturePins.interpreterSha256,identity,output,proof,denyNetwork,signal,onReady,unlockMs});
}
export async function runProductionPrivateAcceptance(options){
 // This grant records an externally verified user scope/preflight/custodian;
 // it is never inferred from CI success, a fixture result or an environment flag.
 requireProductionGrant(options?.grant,options?.identity);
 return observeAndExecute({...options,pins:qualification.launcherPins,initSha256:qualification.fixturePins['portable_agent/__init__.py'],api:options.api??github(options.identity.runId,options.identity.head)},false);
}
export async function qualifySyntheticPrivateExecutor(options){
 if(options?.qualificationOnly!==true||!options.api)throw Error('Synthetic qualification required');
 const root=await privateTemporaryDirectory('exp710-production-fixture-');
 try{
  const bytes=await readFile(fileURLToPath(new URL('./private-cli-fixture.py',import.meta.url)));
  if(hash(bytes)!==SYNTHETIC_CLI_SHA256)throw Error('Synthetic CLI changed');
  await mkdir(join(root,'portable_agent'),{mode:0o700});const pins={};
  for(const name of Object.keys(qualification.launcherPins)){
   const data=name==='run_otto_acceptance.py'?bytes:Buffer.from('# synthetic fixture only\n');pins[name]=hash(data);await writeFile(join(root,'portable_agent',name),data,{mode:0o600,flag:'wx'});
  }
  await writeFile(join(root,'portable_agent/__init__.py'),'',{mode:0o600,flag:'wx'});
  const result=await observeAndExecute({...options,source:root,pins,initSha256:hash(Buffer.alloc(0))},true);
  return {...result,qualificationOnly:true,liveRequests:0};
 }finally{await rm(root,{recursive:true,force:true});}
}
const SYNTHETIC_CLI_SHA256='8f52e658db5a108b6a006e13844d62ead0d77e7e7641aefcf393ec32a12997b7';
