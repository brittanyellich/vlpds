// Shared LOCAL gates used by the mutating runner and GET-only diagnostics.
import{readFileSync}from'node:fs';import{execFileSync}from'node:child_process';
import{resolve,join}from'node:path';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';
import{PILOT}from'./pilot-activation-plan.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
export function preflightInputs(env,mode,report=()=>{}) {
 const gate=(stage,run,details={})=>{try{const value=run();report({stage,ok:true,...details});return value;}catch{report({stage,ok:false,...details});throw new Error('Pilot input gate refused');}};
 gate('execution-context',()=>{
  if(!['preflight','provision','activate','wait','disable','cleanup','diagnose'].includes(mode)||env.GITHUB_REPOSITORY!=='brittanyellich/vlpds'||env.GITHUB_REF!=='refs/heads/main'||env.GITHUB_RUN_ATTEMPT!=='1'||!/^\d+$/.test(env.GITHUB_RUN_ID??'')||!/^[a-f0-9]{40}$/.test(env.GITHUB_SHA??'')||!env.RUNNER_TEMP?.startsWith('/home/runner/work/_temp'))throw 0;
 });
 const card=env.PILOT_CARD_JSON;
 const receivedCardSha256=typeof card==='string'?createHash('sha256').update(card).digest('hex'):null;
 gate('signed-card-input',()=>{if(receivedCardSha256!==PILOT.cardHash)throw 0;},{expectedCardSha256:PILOT.cardHash,receivedCardSha256});
 gate('qualified-source',()=>execFileSync('git',['diff','--exit-code',PILOT.revision,'HEAD','--','deploy/cloudflare/src','deploy/cloudflare/package-lock.json',':(exclude)deploy/cloudflare/src/index.ts',':(exclude)deploy/cloudflare/src/runtime.ts'],{cwd:resolve(root,'../..'),stdio:'pipe',env:{PATH:'/usr/bin:/bin'},timeout:10000}));
 const bytes=gate('worker-qualification',()=>{
  const bytes=readFileSync(join(root,'scripts/pilot-worker-qualification.json')),q=JSON.parse(bytes);
  if(q.version!==1||q.nativeImageDigest!==PILOT.digest||q.nativeSourceRevision!==PILOT.revision||JSON.stringify(Object.keys(q.files).sort())!==JSON.stringify(['package.json','src/index.ts','src/runtime.ts']))throw 0;
  for(const [file,hash]of Object.entries(q.files))if(createHash('sha256').update(readFileSync(join(root,file))).digest('hex')!==hash)throw 0;
  return bytes;
 });
 const identity={workerQualificationSha256:createHash('sha256').update(bytes).digest('hex'),repository:env.GITHUB_REPOSITORY,runId:Number(env.GITHUB_RUN_ID),head:env.GITHUB_SHA};
 return {root,card,identity,stateFile:join(env.RUNNER_TEMP,'exp710-pilot-state.json'),receiptFile:join(env.RUNNER_TEMP,'exp710-activation-ready.json')};
}
