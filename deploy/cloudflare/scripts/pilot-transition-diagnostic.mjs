import {ProviderPending,CardPending,CARD_PENDING_REASONS} from './pilot-provider.mjs';
const stages=['load-state','phase-lease','fresh-off-state','save-attempt','publish-ack','worker-config','save-worker','runtime-restart','readiness','persist-active','reconcile-provisioned-off','persist-disabled'];
const checks=['runtime-status','card-authority','worker-metadata','worker-bindings','public-checks','runtime-status-final','not-started'];
const reasons=['none','request-unavailable','upstream-pending','runtime-starting','ui-pending','card-pending','provider-pending','gate-refused',...CARD_PENDING_REASONS];
export function transitionReason(error){
 if(error instanceof CardPending&&CARD_PENDING_REASONS.includes(error.reason))return error.reason;
 if(!(error instanceof ProviderPending))return 'gate-refused';
 return ({'Provider unavailable':'request-unavailable','Provider pending':'upstream-pending','Container pending':'runtime-starting','UI pending':'ui-pending','Card pending':'card-pending'})[error.message]??'provider-pending';
}
// Only fixed codes and locally measured durations. Never serialize exceptions,
// provider responses, private state, credentials or caller-supplied strings.
export function transitionDiagnostic(phase,identity,write,clock=()=>performance.now()){
 const keys=['workerQualificationSha256','repository','runId','head'];
 if(!['activate','disable'].includes(phase)||!identity||JSON.stringify(Object.keys(identity).sort())!==JSON.stringify([...keys].sort())||identity.repository!=='brittanyellich/vlpds'||!Number.isSafeInteger(identity.runId)||identity.runId<=0||!/^[a-f0-9]{40}$/.test(identity.head??'')||!/^[a-f0-9]{64}$/.test(identity.workerQualificationSha256??''))throw new Error('Transition diagnostic identity refused');
 const start=clock();let previous=start;
 const receipt={version:1,kind:'exp710-transition-diagnostic',phase,readyForPilot:false,...Object.fromEntries(keys.map(k=>[k,identity[k]])),steps:[],polls:[]};
 return(stage,status,info={})=>{
  const at=clock();if(!Number.isFinite(at)||!Number.isFinite(start)||at<previous)throw new Error('Transition diagnostic clock refused');previous=at;
  const elapsedMs=Math.floor(at-start);
  if(stage==='readiness-poll'){
   if(!['passed','pending','failed'].includes(status)||!Number.isInteger(info.attempt)||info.attempt!==receipt.polls.length+1||info.attempt>20||!checks.includes(info.check)||!reasons.includes(info.reason))throw new Error('Transition diagnostic poll refused');
   receipt.polls.push({attempt:info.attempt,status,check:info.check,reason:info.reason,elapsedMs});
  }else{
   if(!stages.includes(stage)||!['started','passed','failed'].includes(status))throw new Error('Transition diagnostic stage refused');
   let row=receipt.steps.find(r=>r.stage===stage);
   if(status==='started'){if(row)throw new Error('Duplicate transition stage');row={stage,status,startedMs:elapsedMs};receipt.steps.push(row);}
   else{if(row?.status!=='started')throw new Error('Transition diagnostic order refused');Object.assign(row,{status,completedMs:elapsedMs,durationMs:elapsedMs-row.startedMs});if(status==='failed'&&reasons.includes(info.reason))row.reason=info.reason;}
  }
  write(JSON.stringify(receipt));
 };
}
// Observability must never interrupt mandatory OFF or change a safety gate.
export function bestEffortTransition(report,onUnavailable=()=>{}){
 let unavailable=false;
 return(...args)=>{if(unavailable)return;try{report(...args);}catch{unavailable=true;try{onUnavailable();}catch{/* no exception data */}}};
}
export function createTransitionReporter(phase,identity,write,onUnavailable=()=>{},clock){
 try{return bestEffortTransition(transitionDiagnostic(phase,identity,write,clock),onUnavailable);}
 catch{try{onUnavailable();}catch{/* diagnostic setup cannot block OFF */}return()=>{};}
}
