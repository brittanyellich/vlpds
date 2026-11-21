// Only the reviewed production Actions workflow may invoke this CLI. No profile
// mint/revoke or public repo write is implemented here.
import {readFileSync,writeFileSync,appendFileSync,existsSync,mkdtempSync,rmSync}from'node:fs';
import {publishPilotWorker}from'./pilot-publish.mjs';import{join,resolve}from'node:path';
import{preflightInputs}from'./pilot-preflight-inputs.mjs';
import{checkCandidateToken}from'./pilot-token-check.mjs';
import{provisionDiagnostic}from'./pilot-provision-diagnostic.mjs';
import{createTransitionReporter}from'./pilot-transition-diagnostic.mjs';
import{sealState,openState}from'./pilot-state.mjs';import{fileURLToPath}from'node:url';
import{PILOT,normalizeCredentialMetadata}from'./pilot-activation-plan.mjs';
import{preparePilotConfig}from'./pilot-config.mjs';import{PilotProvider}from'./pilot-provider.mjs';
import{PilotLifecycle}from'./pilot-lifecycle.mjs';import{cloudflareSecretTransport}from'./pilot-secret-transport.mjs';
const env=process.env,now=()=>Math.floor(Date.now()/1000),sleep=ms=>new Promise(r=>setTimeout(r,ms));
const mode=process.argv[2],root=resolve(fileURLToPath(new URL('..',import.meta.url)));
let stateFile,receiptFile;
const safeEmit=value=>console.log(JSON.stringify(value));
async function main(){
 if(!['preflight','provision','activate','wait','disable','cleanup'].includes(mode))throw 0;
 const context=preflightInputs(env,mode);
 stateFile=context.stateFile;receiptFile=context.receiptFile;
 const {card,identity}=context;
 const reportProvision=mode==='provision'?provisionDiagnostic(identity,bytes=>writeFileSync(join(env.RUNNER_TEMP,'exp710-provision-diagnostic.json'),bytes,{mode:0o600})):()=>{};
 const reportTransition=['activate','disable'].includes(mode)?createTransitionReporter(mode,identity,bytes=>writeFileSync(join(env.RUNNER_TEMP,`exp710-${mode}-diagnostic.json`),bytes,{mode:0o600}),()=>safeEmit({kind:'exp710-transition-diagnostic-unavailable',phase:mode})):()=>{};
 const save=s=>writeFileSync(stateFile,sealState(s,env.VLPDS_DEPLOY_TOKEN),{mode:0o600});
 const load=()=>openState(readFileSync(stateFile),env.VLPDS_DEPLOY_TOKEN,identity);
 const provider=new PilotProvider({account:env.CLOUDFLARE_ACCOUNT_ID,cfToken:env.CLOUDFLARE_API_TOKEN,deployToken:env.VLPDS_DEPLOY_TOKEN,fetchImpl:fetch,now});
 const deploy=async (enabled,deadline)=>{
  const config=preparePilotConfig({...env,DEPLOY_TOKEN:env.VLPDS_DEPLOY_TOKEN},card,enabled,deadline);
  const tmp=mkdtempSync(join(env.RUNNER_TEMP,'exp710-config-'));
  // Config's main path resolves relative to this file; use an absolute reviewed
  // source path, same module as the qualified OFF Worker. Image remains pinned.
  config.main=join(root,'src/index.ts');const path=join(tmp,'pilot.json');writeFileSync(path,JSON.stringify(config),{mode:0o600});
  try {return publishPilotWorker({root,tmp,configPath:path,account:env.CLOUDFLARE_ACCOUNT_ID,token:env.CLOUDFLARE_API_TOKEN});}finally{rmSync(tmp,{recursive:true,force:true});}
 };
 const remove=async()=>{
  // Null deletes only the two pilot bindings via the same documented bulk API.
  const url=provider.api+'/secrets-bulk';let response;
  try {response=await fetch(url,{method:'PATCH',redirect:'error',signal:AbortSignal.timeout(15000),headers:{Authorization:`Bearer ${env.CLOUDFLARE_API_TOKEN}`,'Content-Type':'application/merge-patch+json'},body:JSON.stringify({secrets:{AGENT_A2A_BRIDGE_KEY:null,AGENT_A2A_KODY_TOKEN:null}})});
   if(response.status!==200)throw 0; // Independent binding readback follows.
  }finally{await response?.body?.cancel().catch(()=>{});}
 };
 const lifecycle=new PilotLifecycle({provider,save,load,deploy,provision:cloudflareSecretTransport(fetch),introspect:(token,o)=>checkCandidateToken(token,{...o,fetchImpl:fetch,clock:now}),remove,card,now,sleep,identity,reportProvision,reportActivation:mode==='activate'?reportTransition:()=>{},reportOff:mode==='disable'?reportTransition:()=>{}});
 if(mode==='preflight'){
  if(existsSync(stateFile))throw 0;
  preparePilotConfig({...env,DEPLOY_TOKEN:env.VLPDS_DEPLOY_TOKEN},card,false);
  const credential=normalizeCredentialMetadata(JSON.parse(env.PILOT_CREDENTIAL_METADATA),{now:now(),expectedOrg:PILOT.org});
  await lifecycle.preflight({account:env.CLOUDFLARE_ACCOUNT_ID,credential});safeEmit({kind:'exp710-preflight',...identity,digest:PILOT.digest});
 }else if(mode==='provision'){
  await lifecycle.provisionSecrets({bridgeKey:env.VLPDS_AGENT_BRIDGE_KEY,profileToken:env.VLPDS_AGENT_KODY_TOKEN,cloudflareToken:env.CLOUDFLARE_API_TOKEN,account:env.CLOUDFLARE_ACCOUNT_ID});safeEmit({kind:'exp710-provisioned-off',...identity});
 }else if(mode==='activate'){
  const receipt=await lifecycle.activate();writeFileSync(receiptFile,JSON.stringify(receipt),{mode:0o600});safeEmit(receipt);
 }else if(mode==='wait'){
  const s=load();if(s.phase!=='active')throw 0;while(now()<s.deadline){try{const {meta}=await lifecycle.inspect(true,true,s.baseline,s.deadline);if(meta.id!==s.activeWorker)throw 0;}catch(e){if(now()>=s.deadline)break;throw e;}await sleep(Math.min(10000,(s.deadline-now())*1000));}safeEmit({kind:'exp710-window-ended',...identity});
 }else if(mode==='disable'){
  if(!existsSync(stateFile)){safeEmit({kind:'exp710-no-state-no-mutation',...identity});return;}
  const s=load();if(s.phase==='preflight'){safeEmit({kind:'exp710-no-provision-no-mutation',...identity});return;}
  await lifecycle.disable();safeEmit({kind:'exp710-disabled',...identity});
 }else if(mode==='cleanup'){
  if(!existsSync(stateFile))return;const s=load();if(s.phase==='preflight')return;
  const receipt=await lifecycle.cleanup();receipt.checkedAt=now();receipt.maxExpiresAt=s.credential.maxExpiresAt;
  writeFileSync(join(env.RUNNER_TEMP,'exp710-off-cleaned.json'),JSON.stringify(receipt),{mode:0o600});
  if(env.GITHUB_OUTPUT)appendFileSync(env.GITHUB_OUTPUT,'receipt=true\n');
  safeEmit(receipt);
 }
}
main().catch(()=>{safeEmit({kind:'exp710-failed',phase:['preflight','provision','activate','wait','disable','cleanup'].includes(mode)?mode:'invalid',reconcile:true});process.exitCode=1;});
