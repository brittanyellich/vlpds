// Real launcher command qualification only. Only the pinned network-denied fixture snapshot can execute.
import{watchReceipt}from'./rollout-observer.mjs';
import{verifiedLauncherPlan,claimRun,rehearseConsumerFixture}from'./rollout-terminal.mjs';
const preparedPlans=new WeakMap();
import{dirname}from'node:path';
import{PILOT}from'../../deploy/cloudflare/scripts/pilot-activation-plan.mjs';
export async function prepareObservedLauncher({authorization,identity,source,python,pins,output,claimDirectory,api,mode,clock=()=>Math.floor(Date.now()/1000),watch={}}){
 if(authorization?.scope!=='local-qualification'||authorization.liveExecutionEnabled!==false||
    authorization.approvedHead!==identity?.head||authorization.baselineWorker!==PILOT.offWorker||
    !['fixture','historical'].includes(mode)||!api)throw Error('Private launch qualification refused');
 const plan=await verifiedLauncherPlan({source,python,pins,identity,output});
 if(!await claimRun(claimDirectory,identity))throw Error('Duplicate private launch refused');
 // archive cannot be supplied through watch options to turn a live proof into history.
 const proof=await watchReceipt(api,identity,{...watch,archive:mode==='historical'});
 if(mode==='fixture'){
  const now=clock();
  if(!Number.isSafeInteger(now)||now<proof.checkedAt||now-proof.checkedAt>120||proof.deadline-now<180)
   throw Error('Private launch window refused');
 }
 Object.freeze(plan.args);Object.freeze(plan);Object.freeze(proof);
 const prepared=Object.freeze({qualificationOnly:true,liveExecutionEnabled:false,historical:mode==='historical',independentlyRecheckRequired:true,proof,plan});
 preparedPlans.set(prepared,{mode,source,python,pins:{...pins},identity:{...identity},consumed:false});
 return prepared;
}

// No arbitrary command, password or production transport may enter this seam.
export async function executePrivateLauncherFixture(prepared,directory,{bundle,fixturePins,action='input'}={}){
 const saved=preparedPlans.get(prepared);
 if(!saved||saved.mode!=='fixture'||saved.consumed)throw Error('Private fixture executor refused');
 saved.consumed=true;
 if(!['input','timeout','stop'].includes(action)||bundle?.rehearsalOnly!==true||
    bundle.run?.id!==saved.identity.runId||bundle.run?.head_sha!==saved.identity.head||
    bundle.checkedAt!==prepared.proof.checkedAt||bundle.deadline!==prepared.proof.deadline)
  throw Error('Private fixture inputs refused');
 if(dirname(prepared.plan.args[4])!==directory)throw Error('Private fixture output refused');
 await verifiedLauncherPlan({source:saved.source,python:saved.python,pins:saved.pins,identity:saved.identity,output:prepared.plan.args[4]});
 return rehearseConsumerFixture(directory,{source:saved.source,python:saved.python,pins:saved.pins,fixturePins,
  bundle:{...bundle,launcherArgs:[...prepared.plan.args],entry:'operator-cli-fixture',privateInputSeconds:action==='timeout'?0.5:5},
  terminalApp:true,fixtureAction:action,includeCliFixture:true});
}
