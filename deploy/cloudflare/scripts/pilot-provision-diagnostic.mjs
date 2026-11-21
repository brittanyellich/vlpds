import {CANDIDATE_STAGES,CandidateTokenRefused} from './pilot-token-check.mjs';
export const PROVISION_STAGES=Object.freeze(['load-private-state','phase-and-lease','fresh-off-state','candidate-introspection','persist-provision-attempt','transfer-two-bindings','verify-provisioned-off','persist-provisioned-state']);
// Fixed codes only. Never copy an exception, HTTP body/header, credential or
// private state into a receipt. This receipt cannot authorize a pilot or retry.
export function provisionDiagnostic(identity,write){
 const keys=['workerQualificationSha256','repository','runId','head'];
 if(!identity||JSON.stringify(Object.keys(identity).sort())!==JSON.stringify([...keys].sort())||identity.repository!=='brittanyellich/vlpds'||!Number.isSafeInteger(identity.runId)||identity.runId<=0||!/^[a-f0-9]{40}$/.test(identity.head??'')||!/^[a-f0-9]{64}$/.test(identity.workerQualificationSha256??''))throw new Error('Diagnostic identity refused');
 const receipt={version:1,kind:'exp710-provision-diagnostic',readyForPilot:false,...Object.fromEntries(keys.map(k=>[k,identity[k]])),steps:[]};
 return (stage,status,error)=>{
  if(!PROVISION_STAGES.includes(stage)||!['started','passed','failed'].includes(status))throw new Error('Diagnostic stage refused');
  const row={stage,status};
  if(status==='failed'&&stage==='candidate-introspection'&&error instanceof CandidateTokenRefused&&CANDIDATE_STAGES.includes(error.stage))row.candidateStage=error.stage;
  const last=receipt.steps.at(-1);
  if(status==='started')receipt.steps.push(row);
  else{if(last?.stage!==stage||last.status!=='started')throw new Error('Diagnostic order refused');receipt.steps[receipt.steps.length-1]=row;}
  write(JSON.stringify(receipt));
 };
}
