// Incident-only reconciliation. No Worker upload, restart, activation or mint.
import{PilotProvider,checkBindings,ProviderPending}from'./pilot-provider.mjs';import{PILOT}from'./pilot-activation-plan.mjs';
import{createHash}from'node:crypto';import{writeFileSync}from'node:fs';import{join,isAbsolute}from'node:path';import{pathToFileURL}from'node:url';
export const CLEANUP=Object.freeze({worker:'37d6aa2e-607f-442f-88b7-54e6c2c5e86c',script:'88f6a917a64c75dda70dd40bb76cc74c8607790400fd50349095ec7fe615dc42',
 provisionedTypes:'391439edd899f411421542bb7bee96c82485534096ebaf71a9449a99b9ce8d11',cleanTypes:'0fc25600babf6b573a96519018b704a676c59723f09f83ba89de0b27f3c0c5ad'});
const body=JSON.stringify({secrets:{AGENT_A2A_BRIDGE_KEY:null,AGENT_A2A_KODY_TOKEN:null}});
export async function reconcileBindings({provider,remove,operation,exclusiveWindow=false,now=()=>performance.now(),sleep=ms=>new Promise(r=>setTimeout(r,ms))}){
 const receipt={version:1,kind:'exp710-binding-reconciliation',operation:['inspect','cleanup'].includes(operation)?operation:'invalid',expectedDigest:PILOT.digest,deleteAttempted:false,deleteAcknowledged:false,exclusiveWindowConfirmed:exclusiveWindow===true,atomicApiPrecondition:false,result:'failed',checks:[]};
 let stage='operation';
 const snapshot=async(label)=>{
  const started=now();stage=label+'-qualified-runtime';await provider.status();stage=label+'-worker';const meta=await provider.metadata();
  const pairs=meta.bindings.map(b=>[b.name,b.type]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0),hash=createHash('sha256').update(JSON.stringify(pairs)).digest('hex');
  const enabled=meta.bindings.find(b=>b.name==='AGENT_A2A_ENABLED');const expires=meta.bindings.find(b=>b.name==='AGENT_A2A_EXPIRES_AT');
  const safe={stage:label,workerVersion:meta.id,scriptEtag:meta.scriptEtag,bindingCount:meta.bindings.length,nameTypeHash:hash,enabledFalse:enabled?.type==='plain_text'&&enabled.text==='false',leaseAbsent:expires===undefined};
  receipt.checks.push(safe);
  if(meta.scriptEtag!==CLEANUP.script||![CLEANUP.cleanTypes,CLEANUP.provisionedTypes].includes(hash))throw new Error('Unexpected script or bindings');
  const provisioned=hash===CLEANUP.provisionedTypes;stage=label+'-off';const ordinary=checkBindings(meta,{enabled:false,provisioned});
  stage=label+'-public-health';await provider.publicChecks(false);await provider.status();if(now()-started>30000)throw new Error('Stale snapshot');
  return{meta,ordinary,provisioned};
 };
 try{
  if(!['inspect','cleanup'].includes(operation))throw 0;
  const before=await snapshot('before');
  if(!before.provisioned){receipt.result='already-clean';receipt.offVerified=true;return receipt;}
  if(operation==='inspect'){receipt.result='off-with-pilot-bindings';receipt.offVerified=true;return receipt;}
  stage='exclusive-writer-window';if(exclusiveWindow!==true)throw 0;
  stage='expected-worker';if(before.meta.id!==CLEANUP.worker)throw 0;
  // Secrets-bulk has no documented version CAS. Actions concurrency plus an
  // explicit operator/dashboard write freeze is REQUIRED; this final read only
  // narrows the residual race and must not be described as atomic protection.
  stage='fresh-worker-confirmation';const freshAt=now(),fresh=await provider.metadata();
  if(fresh.id!==before.meta.id||fresh.scriptEtag!==before.meta.scriptEtag||checkBindings(fresh,{enabled:false,provisioned:true})!==before.ordinary)throw 0;
  await provider.status();if(now()-freshAt>5000)throw 0;
  stage='delete-two-bindings';receipt.deleteAttempted=true;
  // An ambiguous response is reconciled by reads, never a repeated mutation.
  try{receipt.deleteAcknowledged=await remove()===true;}catch{/* no raw error or retry */}
  const until=now()+90000;
  while(now()<until){
   try{
    const after=await snapshot('after');stage='unchanged-ordinary-bindings';if(after.ordinary!==before.ordinary)throw new Error('Ordinary binding drift');
    if(!after.provisioned){receipt.result='verified-clean';receipt.offVerified=true;return receipt;}
   }catch(e){if(!(e instanceof ProviderPending))throw e;}
   await sleep(Math.max(0,Math.min(3000,until-now())));
  }
  stage='delete-readback-timeout';throw 0;
 }catch{receipt.failedStage=stage;return receipt;}
}
export async function deleteOnlyPilotBindings(fetchImpl,provider){
 let response;try{
  if(!/^https:\/\/api\.cloudflare\.com\/client\/v4\/accounts\/[a-f0-9]{32}\/workers\/scripts\/crate-pds$/.test(provider.api??'')||!/^[A-Za-z0-9_-]{20,256}$/.test(provider.cfToken??''))return false;
  response=await fetchImpl(provider.api+'/secrets-bulk',{method:'PATCH',redirect:'error',signal:AbortSignal.timeout(15000),headers:{Authorization:`Bearer ${provider.cfToken}`,'Content-Type':'application/merge-patch+json','Accept-Encoding':'identity'},body});
  if(response.status!==200||response.headers.get('content-type')?.split(';')[0]!=='application/json')return false;
  const reader=response.body.getReader(),parts=[];let size=0;
  try{while(true){const{done,value}=await reader.read();if(done)break;size+=value.length;if(size>8192)throw 0;parts.push(value);}}finally{await reader.cancel().catch(()=>{});}
  return JSON.parse(Buffer.concat(parts)).success===true;
 }catch{return false;}finally{await response?.body?.cancel().catch(()=>{});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 let result;try{
  const e=process.env;if(e.GITHUB_REPOSITORY!=='brittanyellich/vlpds'||e.GITHUB_REF!=='refs/heads/main'||e.GITHUB_RUN_ATTEMPT!=='1')throw 0;
  const provider=new PilotProvider({account:e.CLOUDFLARE_ACCOUNT_ID,cfToken:e.CLOUDFLARE_API_TOKEN,deployToken:e.VLPDS_DEPLOY_TOKEN,fetchImpl:(url,o)=>{if(o.method!=='GET')throw new Error('Read-only provider');return fetch(url,o);}});
  result=await reconcileBindings({provider,operation:process.argv[2],exclusiveWindow:e.EXCLUSIVE_WINDOW_CONFIRMED==='true',remove:()=>deleteOnlyPilotBindings(fetch,provider)});
 }catch{result={version:1,kind:'exp710-binding-reconciliation',result:'failed',failedStage:'execution-context',deleteAttempted:false};}
 if(process.env.GITHUB_ACTIONS==='true'&&typeof process.env.RUNNER_TEMP==='string'&&isAbsolute(process.env.RUNNER_TEMP)){
  try{writeFileSync(join(process.env.RUNNER_TEMP,'exp710-binding-reconciliation.json'),JSON.stringify(result),{mode:0o600,flag:'wx'});}catch{console.error('Reconciliation receipt write failed');process.exitCode=1;}
 }
 console.log(JSON.stringify(result));if(result.result==='failed')process.exitCode=1;
}
