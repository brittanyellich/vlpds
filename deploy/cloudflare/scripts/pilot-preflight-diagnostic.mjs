// Read-only diagnostic: no Kody credential, secret write, deployment or restart.
import{writeFileSync}from'node:fs';import{createHash}from'node:crypto';import{join,isAbsolute}from'node:path';import{pathToFileURL}from'node:url';
import{preflightInputs}from'./pilot-preflight-inputs.mjs';import{preparePilotConfig}from'./pilot-config.mjs';
import{PilotProvider,checkBindings}from'./pilot-provider.mjs';import{PILOT}from'./pilot-activation-plan.mjs';
const DID='https://plc.directory/did:plc:6tlvgafuonoighfrtpejff5m';
// Exact 23 name/type pairs from approved immutable OFF Worker7572 metadata.
const EXPECTED_BINDING_TYPES='0fc25600babf6b573a96519018b704a676c59723f09f83ba89de0b27f3c0c5ad';
export async function preflightDiagnostic(env,fetchImpl,{inputs=preflightInputs,configuration=preparePilotConfig}={}) {
 const checks=[];let identity={},didMedia='not-observed';
 const step=async(stage,run)=>{try{const details=await run();checks.push({stage,ok:true,...details});}catch{checks.push({stage,ok:false});throw new Error('Diagnostic gate refused');}};
 try{
  const context=inputs(env,'diagnose',row=>checks.push(row));identity=context.identity;
  await step('pilot-credentials-absent',async()=>{if(env.VLPDS_AGENT_KODY_TOKEN||env.VLPDS_AGENT_BRIDGE_KEY)throw 0;return {};});
  let provider;
  await step('provider-credentials',async()=>{provider=new PilotProvider({account:env.CLOUDFLARE_ACCOUNT_ID,cfToken:env.CLOUDFLARE_API_TOKEN,deployToken:env.VLPDS_DEPLOY_TOKEN,
   fetchImpl:async(url,options)=>{
    if(options.method!=='GET')throw new Error('Diagnostic permits GET only');
    const response=await fetchImpl(url,options);
    if(url===DID){const type=response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();didMedia=['application/json','application/did+ld+json'].includes(type)?type:'other';}
    return response;
   }});return {};});
  await step('production-config',async()=>{configuration({...env,DEPLOY_TOKEN:env.VLPDS_DEPLOY_TOKEN},context.card,false);return {};});
  await step('qualified-runtime-status',async()=>{
   const s=await provider.json('https://admin.crate.social/_deploy/status',{limit:4096});
   const safeImage=value=>value===null?null:typeof value==='string'&&new RegExp('^registry\\.cloudflare\\.com/'+provider.account+'/(?:vlpds|crate-pds-pds-pds)@sha256:[a-f0-9]{64}$').test(value)?value.replace('/'+provider.account+'/','/<account>/'):'unrecognized';
   const details={desired:safeImage(s.desired),current:safeImage(s.current),running:typeof s.running==='boolean'?s.running:'invalid'};
   if(s.desired!==provider.image||s.current!==provider.image||s.running!==true){checks.push({stage:'status-comparison',ok:false,...details});throw 0;}return details;
  });
  await step('current-card-authority',async()=>{await provider.currentCardKey();return {expectedKeyAndOriginMatch:true};});
  await step('off-worker-bindings',async()=>{
   const m=await provider.metadata();const pairs=m.bindings.map(b=>[b.name,b.type]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
   const nameTypeHash=createHash('sha256').update(JSON.stringify(pairs)).digest('hex');
   const details={workerVersion:m.id,scriptEtag:m.scriptEtag,bindingCount:m.bindings.length,nameTypeHash,expectedWorkerMatch:m.id===PILOT.offWorker,expectedBindingTypesMatch:nameTypeHash===EXPECTED_BINDING_TYPES};
   if(!details.expectedWorkerMatch||!details.expectedBindingTypesMatch){checks.push({stage:'worker-comparison',ok:false,...details});throw 0;}
   checkBindings(m,{enabled:false,provisioned:false});return details;
  });
  await step('public-health-ui-card-off',async()=>{await provider.publicChecks(false);return {health:200,ui:200,card:404};});
 }catch{/* Never serialize exception text, inputs, headers or raw response data. */}
 const failed=checks.some(x=>x.ok===false);const complete=checks.at(-1)?.stage==='public-health-ui-card-off'&&checks.at(-1)?.ok===true;
 return {version:1,kind:'exp710-preflight-diagnostic',readOnly:true,readyForPilot:false,...identity,expectedDigest:PILOT.digest,didMediaType:didMedia,result:!failed&&complete?'passed':'failed',credentialProof:'not-attempted',checks};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const receipt=await preflightDiagnostic(process.env,fetch);
 // Only the fixed Actions temp destination; no user output path or raw input.
 if(process.env.GITHUB_ACTIONS==='true'&&typeof process.env.RUNNER_TEMP==='string'&&isAbsolute(process.env.RUNNER_TEMP)){try{writeFileSync(join(process.env.RUNNER_TEMP,'exp710-preflight-diagnostic.json'),JSON.stringify(receipt),{mode:0o600,flag:'wx'});}catch{console.error('Diagnostic receipt write failed');process.exitCode=1;}}
 console.log(JSON.stringify(receipt));if(receipt.result!=='passed')process.exitCode=1;
}
