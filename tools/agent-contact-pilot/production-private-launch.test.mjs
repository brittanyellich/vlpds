import test from'node:test';import assert from'node:assert/strict';
import{readFile,rm,lstat}from'node:fs/promises';import{join}from'node:path';import{createHash}from'node:crypto';
import{requireProductionGrant,runProductionPrivateAcceptance,qualifySyntheticPrivateExecutor}from'./production-private-launch.mjs';
import{requireExecutionWindow,verifyPrivateCompletion,qualifiedPythonRuntime,verifiedOwnedCleanup}from'./owned-private-cli.mjs';import{privateTemporaryDirectory}from'./rollout-private-temp.mjs';
import{childBytes}from'./rollout-observer.mjs';import{PILOT}from'../../deploy/cloudflare/scripts/pilot-activation-plan.mjs';
const identity={runId:112233,head:'ae46055964be329f88fb4ae0152cebb0aa83f825'};
const grant={kind:'one-bounded-hosted-otto',approved:true,...identity,baselineWorker:PILOT.offWorker,leaseSeconds:600,preflightRunId:112232,preflightHead:identity.head,preflightVerified:true,productionExecutionQualified:true,custodianAvailable:true,operatorAvailable:true};
test('exact production grant is explicit and every prerequisite is required',async()=>{
 requireProductionGrant(grant,identity);
 for(const patch of [{},{approved:false},{runId:1},{head:'b'.repeat(40)},{baselineWorker:'old'},{leaseSeconds:601},{preflightRunId:0},{preflightRunId:identity.runId},{preflightHead:"b".repeat(40)},{preflightVerified:false},{productionExecutionQualified:false},{custodianAvailable:false},{operatorAvailable:false}]){
  const candidate=Object.keys(patch).length?{...grant,...patch}:undefined;
  await assert.rejects(runProductionPrivateAcceptance({identity,grant:candidate,api:{get:()=>{throw Error('must not observe');}}}),/grant required/);
 }
});
test('execution window refuses future/stale/short proof; exact bounds retained',()=>{
 requireExecutionWindow({checkedAt:1000,deadline:1300},1120);
 for(const[p,n]of [[{checkedAt:1000,deadline:1300},1121],[{checkedAt:1000,deadline:1600},999],[{checkedAt:1000,deadline:1299},1120],[{checkedAt:1000,deadline:1601},1000]])assert.throws(()=>requireExecutionWindow(p,n));
});
async function apiFixture(){
 const now=Math.floor(Date.now()/1000);const receipt={version:1,kind:'exp710-activation-ready',workerQualificationSha256:'253b25c2baa4983042d803787b60ec0be9838c253b4860761257d0795b345e36',repository:'brittanyellich/vlpds',runId:identity.runId,head:identity.head,digest:PILOT.digest,workerVersion:'12345678-1234-1234-1234-123456789abc',caller:PILOT.caller,recipient:'did:plc:6tlvgafuonoighfrtpejff5m',profile:PILOT.profile,artifactRevision:PILOT.revision,cardKey:PILOT.cardKey,cardArtifactSha256:PILOT.cardHash,cardPayloadSha256:'0239e2b2eb803c6865f8f7f62203da37eeba64f11ceea25a05a54735d866bf43',checkedAt:now,deadline:now+600};
 const zip=await childBytes('python3',['-c',"import sys,io,zipfile; b=io.BytesIO();z=zipfile.ZipFile(b,'w');z.writestr('exp710-activation-ready.json',sys.stdin.buffer.read());z.close();sys.stdout.buffer.write(b.getvalue())"],{input:Buffer.from(JSON.stringify(receipt))});
 const run={id:identity.runId,repository:{full_name:'brittanyellich/vlpds'},head_sha:identity.head,head_branch:'main',run_attempt:1,event:'workflow_dispatch',path:'.github/workflows/cloudflare-agent-pilot.yml',status:'in_progress',conclusion:null};
 const jobs={total_count:1,jobs:[{name:'pilot',run_id:identity.runId,head_sha:identity.head,steps:['Activate guarded Otto-only pilot','Publish sanitized activation-ready receipt'].map(name=>({name,status:'completed',conclusion:'success'}))}]};
 const artifacts={total_count:1,artifacts:[{id:42,name:`exp710-activation-ready-${identity.runId}`,workflow_run:{id:identity.runId,head_sha:identity.head},expired:false,size_in_bytes:zip.length,digest:'sha256:'+createHash('sha256').update(zip).digest('hex')}]};
 let reads=0;return{run,api:{get:async p=>{reads++;return p.endsWith('/zip')?zip:Buffer.from(JSON.stringify(p.includes('/jobs?')?jobs:p.includes('/artifacts?')?artifacts:run));}},reads:()=>reads};
}
const native=process.env.EXP710_PRODUCTION_EXECUTOR_FIXTURE==='1'&&Boolean(process.env.EXP710_REHEARSAL_PYTHON);
for(const action of ['input','timeout','stop'])test(`shared actual-CLI Terminal primitive ${action}`,{skip:!native},async()=>{
 const root=await privateTemporaryDirectory('exp710-production-test-');const f=await apiFixture();const controller=new AbortController();let ready=0;
 const options={qualificationOnly:true,identity,python:process.env.EXP710_REHEARSAL_PYTHON,output:join(root,'acceptance.json'),claimDirectory:root,api:f.api,signal:controller.signal,unlockMs:action==='timeout'?250:60000,onReady:async event=>{ready++;assert.equal(event.echoDisabled,true);if(action==='input')await childBytes('osascript',['-e',`tell application "Terminal" to do script "SYNTHETIC_ONLY" in window id ${event.windowId}`]);if(action==='stop')controller.abort();}};
 try{
  const result=await qualifySyntheticPrivateExecutor(options);console.log(JSON.stringify({action,ready,...result}));assert.equal(result.result,action==='input'?'PASS':'FAIL');assert.equal(result.liveRequests,0);assert.equal(ready,1);assert.equal(result.echoRestored,true);assert.equal(result.privateInputReached,true);assert.equal(result.cleanupVerified,true);assert.equal(result.ownedWindowClosed,true);assert.equal(result.ownedProcessGroup,true);
  if(action==='input'){assert.equal((await lstat(options.output)).mode&0o077,0);assert.equal(JSON.parse(await readFile(options.output)).result,'PASS');}
  else await assert.rejects(lstat(options.output),e=>e.code==='ENOENT');
  const before=f.reads();await assert.rejects(qualifySyntheticPrivateExecutor(options),/Duplicate|Output already exists/);assert.equal(f.reads(),before);
 }finally{await rm(root,{recursive:true,force:true});}
});

test('completion cannot race proof expiry, lease floor or abort',()=>{
 const proof={checkedAt:1000,deadline:1300};const done={exitCode:0};const result={result:'PASS',cardSignatureValid:true,caller:'did:plc:vsgwub3c3pupqt3yhxfmecma',audience:'did:web:pds.crate.social',lxm:'chat.atagents.agent.contact',status:'verified',stableRetry:true};
 verifyPrivateCompletion({proof,done,result,unlocked:true,now:1120});
 assert.throws(()=>verifyPrivateCompletion({proof,done,result,unlocked:true,now:1121}));
 assert.throws(()=>verifyPrivateCompletion({proof:{checkedAt:1000,deadline:1299},done,result,unlocked:true,now:1120}));
 const abort=new AbortController();abort.abort();assert.throws(()=>verifyPrivateCompletion({proof,done,result,unlocked:true,now:1120,signal:abort.signal}));
});

test('wrong observed run cannot reach any private Terminal execution',async()=>{
 const root=await privateTemporaryDirectory('exp710-production-proof-');const f=await apiFixture();f.run.id++;
 try{await assert.rejects(qualifySyntheticPrivateExecutor({qualificationOnly:true,identity,python:'/usr/bin/python3',output:join(root,'acceptance.json'),claimDirectory:root,api:f.api,onReady:()=>assert.fail('must not open private input')}),/proof refused/);assert.equal(f.reads(),1);}
 finally{await rm(root,{recursive:true,force:true});}
});

test('execution binds the canonical interpreter and resolved venv dependencies',{skip:!process.env.EXP710_REHEARSAL_PYTHON},async()=>{
 const {realpath,mkdir,symlink,writeFile,unlink}=await import('node:fs/promises');const {dirname}=await import('node:path');
 const python=process.env.EXP710_REHEARSAL_PYTHON;const canonical=await realpath(python);const expected=createHash('sha256').update(await readFile(canonical)).digest('hex');const runtime=await qualifiedPythonRuntime(python,expected);
 const root=await privateTemporaryDirectory('exp710-runtime-pin-');
 try{
  const version=(await childBytes(canonical,['-I','-c','import sys;print(str(sys.version_info.major)+"."+str(sys.version_info.minor))'])).toString().trim();
  await mkdir(join(root,'bin'));await mkdir(join(root,'lib','python'+version),{recursive:true});await symlink(runtime.dependencies,join(root,'lib','python'+version,'site-packages'));await writeFile(join(root,'pyvenv.cfg'),'include-system-site-packages = false\n');
  const alias=join(root,'bin','python');await symlink(canonical,alias);const bound=await qualifiedPythonRuntime(alias,expected);await unlink(alias);await symlink('/not-a-qualified-interpreter',alias);
  assert.equal(bound.command,canonical);assert.equal(bound.dependencies,runtime.dependencies);
  const smoke=await childBytes(bound.command,['-I','-c','import sys;sys.path.insert(0,sys.argv[1]);import httpx,cryptography;print("qualified-imports")',bound.dependencies]);assert.equal(smoke.toString().trim(),'qualified-imports');
 }finally{await rm(root,{recursive:true,force:true});}
});

test('cleanup cannot be verified without an owned process identity and exit',()=>{
 assert.equal(verifiedOwnedCleanup(undefined,true,true),false);assert.equal(verifiedOwnedCleanup({pid:1,pgid:1},true,true),false);assert.equal(verifiedOwnedCleanup({pid:100,pgid:200},true,true),false);
 assert.equal(verifiedOwnedCleanup({pid:100,pgid:100},false,true),false);assert.equal(verifiedOwnedCleanup({pid:100,pgid:100},true,false),false);assert.equal(verifiedOwnedCleanup({pid:100,pgid:100},true,true),true);
});
