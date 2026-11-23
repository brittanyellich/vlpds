import{privateTemporaryDirectory}from'./rollout-private-temp.mjs';
import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,chmod,mkdir,symlink} from 'node:fs/promises';import{tmpdir}from'node:os';import{join}from'node:path';import{createHash}from'node:crypto';
import {observeOnce,watchReceipt,verifyReceipt,childBytes,receiptFromZip}from'./rollout-observer.mjs';
import{claimRun,rehearseTerminal,verifiedLauncherPlan}from'./rollout-terminal.mjs';
import{PILOT}from'../../deploy/cloudflare/scripts/pilot-activation-plan.mjs';
const identity={runId:44220011,head:'a'.repeat(40)};
const receipt={version:1,kind:'exp710-activation-ready',workerQualificationSha256:'253b25c2baa4983042d803787b60ec0be9838c253b4860761257d0795b345e36',repository:'brittanyellich/vlpds',runId:identity.runId,head:identity.head,digest:PILOT.digest,workerVersion:'12345678-1234-1234-1234-123456789abc',caller:PILOT.caller,recipient:'did:plc:6tlvgafuonoighfrtpejff5m',profile:PILOT.profile,artifactRevision:PILOT.revision,cardKey:PILOT.cardKey,cardArtifactSha256:'f02d7b8eb0a81f42fa8b3bcde924af57bc5a21bb4f768e9bff782d51fd4db94f',cardPayloadSha256:'0239e2b2eb803c6865f8f7f62203da37eeba64f11ceea25a05a54735d866bf43',checkedAt:1000,deadline:1600};
function fixture(){
 const bytes=Buffer.from('synthetic-zip'),artifact={id:42,name:`exp710-activation-ready-${identity.runId}`,expired:false,size_in_bytes:bytes.length,digest:'sha256:'+createHash('sha256').update(bytes).digest('hex'),workflow_run:{id:identity.runId,head_sha:identity.head}};
 const run={id:identity.runId,repository:{full_name:'brittanyellich/vlpds'},head_sha:identity.head,head_branch:'main',run_attempt:1,event:'workflow_dispatch',path:'.github/workflows/cloudflare-agent-pilot.yml',status:'in_progress',conclusion:null};
 const jobs={total_count:1,jobs:[{name:'pilot',run_id:identity.runId,head_sha:identity.head,steps:['Activate guarded Otto-only pilot','Publish sanitized activation-ready receipt'].map(name=>({name,status:'completed',conclusion:'success'}))}]};
 const artifacts={total_count:1,artifacts:[artifact]};const api={get:async p=>p.endsWith('/zip')?bytes:Buffer.from(JSON.stringify(p.includes('/jobs?')?jobs:p.includes('/artifacts?')?artifacts:run))};
 return{run,jobs,artifact,artifacts,api,options:{extract:async()=>structuredClone(receipt)}};
}
test('observer validates exact proof before handing off; historical mode distinct',async()=>{const f=fixture();assert.equal((await observeOnce(f.api,identity,f.options)).verified,true);f.run.status='completed';f.run.conclusion='success';await assert.rejects(observeOnce(f.api,identity,f.options));assert.equal((await observeOnce(f.api,identity,{...f.options,archive:true})).verified,true);});
for(const mutate of [f=>f.run.head_sha='b'.repeat(40),f=>f.run.run_attempt=2,f=>f.artifact.workflow_run.head_sha='b'.repeat(40),f=>f.artifact.digest='sha256:'+'0'.repeat(64),f=>f.artifact.expired=true,f=>f.artifacts.artifacts.push(f.artifact),f=>f.artifacts.total_count=101,f=>f.jobs.jobs[0].steps[0].conclusion='failure'])test('refuse malformed run/artifact/job',async()=>{const f=fixture();mutate(f);await assert.rejects(observeOnce(f.api,identity,f.options));});
test('waits before publication and hands off in same process',async()=>{const f=fixture();f.jobs.jobs[0].steps[1].status='pending';let polls=0;const get=f.api.get;f.api.get=async p=>{if(p.includes('/jobs?')&&++polls===2)f.jobs.jobs[0].steps[1].status='completed';return get(p);};assert.equal((await watchReceipt(f.api,identity,{...f.options,intervalMs:1,maxWaitMs:1000})).artifactId,42);assert.equal(polls,2);});
test('missing receipt bounded wait aborts',async()=>{const f=fixture();f.artifacts.artifacts=[];f.artifacts.total_count=0;await assert.rejects(watchReceipt(f.api,identity,{...f.options,intervalMs:1,maxWaitMs:3}));});
test('receipt fixed signed proof pins fail closed',()=>{for(const key of ['cardKey','cardPayloadSha256','caller','profile','head'])assert.throws(()=>verifyReceipt({...receipt,[key]:'wrong'},identity,{id:42,digest:'x'}));assert.throws(()=>verifyReceipt({...receipt,unknown:true},identity,{}));});
test('bounded ZIP parser refuses invalid or extra member',async()=>{await assert.rejects(receiptFromZip(Buffer.from('invalid')));const zip=await childBytes('python3',['-c',"import io,sys,zipfile; b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('other.json','{}'); z.close(); sys.stdout.buffer.write(b.getvalue())"]);await assert.rejects(receiptFromZip(zip));});
test('child output size limit and timeout fail safely',async()=>{await assert.rejects(childBytes(process.execPath,['-e',"process.stdout.write('x'.repeat(1000))"],{maxBytes:10}));await assert.rejects(childBytes(process.execPath,['-e','setTimeout(()=>{},1000)'],{timeoutMs:5}));});
test('atomic durable claim prevents concurrent duplicate launch',async()=>{const dir=await privateTemporaryDirectory('exp710-adapter-');await chmod(dir,0o700);try{const claims=await Promise.all(Array.from({length:10},()=>claimRun(dir,identity)));assert.equal(claims.filter(Boolean).length,1);const b=await readFile(join(dir,`run-${identity.runId}.claim`),'utf8');assert.deepEqual(JSON.parse(b),identity);}finally{await rm(dir,{recursive:true,force:true});}});
test('private directory rejects symlink and public mode',async()=>{const dir=await privateTemporaryDirectory('exp710-adapter-');try{await chmod(dir,0o755);await assert.rejects(claimRun(dir,identity));await chmod(dir,0o700);await symlink(dir,dir+'-link');await assert.rejects(claimRun(dir+'-link',identity));}finally{await rm(dir+'-link',{force:true});await rm(dir,{recursive:true,force:true});}});
test('launcher plan refuses unpinned source before any execution',async()=>{await assert.rejects(verifiedLauncherPlan({source:'/not-present',python:'/usr/bin/python3',pins:{},identity,output:'/private/tmp/result.json'}));});
test('inert PTY adapter requires actual TTY and cannot send requests',async()=>{const dir=await privateTemporaryDirectory('exp710-pty-test-');await chmod(dir,0o700);try{const r=await rehearseTerminal(dir);assert.equal(r.tty,true);assert.equal(r.liveRequests,0);}finally{await rm(dir,{recursive:true,force:true});}});
test('payload hash must use unsigned Card hash, not signed file hash',()=>{assert.throws(()=>verifyReceipt({...receipt,cardPayloadSha256:PILOT.cardHash},identity,{}));});
test('single-process entry refuses duplicate invocation using shared claim directory',async()=>{
 const {rehearseObservedRun}=await import('./rollout-rehearse.mjs');const dir=await privateTemporaryDirectory('exp710-shared-claim-');await chmod(dir,0o700);let reads=0;
 const options={identity,claimDirectory:dir,source:'/unused',python:'/unused',pins:{},api:{get:async()=>{reads++;throw Error('synthetic unavailable');}}};
 try{await assert.rejects(rehearseObservedRun(options));await assert.rejects(rehearseObservedRun(options),/Duplicate rehearsal/);assert.equal(reads,1);}finally{await rm(dir,{recursive:true,force:true});}
});
test('timeout terminates adapter descendants before refusal completes',async()=>{
 const {access}=await import('node:fs/promises');const dir=await privateTemporaryDirectory('exp710-child-cleanup-');const marker=join(dir,'escaped');
 const grandchild=`require('node:fs').writeFileSync(${JSON.stringify(marker)},'unexpected')`;
 const parent=`require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify('setTimeout(()=>{'+grandchild+'},400)')}],{stdio:'ignore'});setTimeout(()=>{},2000)`;
 try{await assert.rejects(childBytes(process.execPath,['-e',parent],{timeoutMs:80}));await new Promise(r=>setTimeout(r,450));await assert.rejects(access(marker));}finally{await rm(dir,{recursive:true,force:true});}
});
test('Terminal cleanup targets created tab window, never front window',async()=>{
 const {writeFile}=await import('node:fs/promises');const dir=await privateTemporaryDirectory('exp710-owned-window-');let closed=false;
 try{const result=await rehearseTerminal(dir,{terminalApp:true,run:async(command,args)=>{assert.equal(command,'osascript');if(args[1].includes('do script')){assert.ok(args[1].includes('tell application \"Terminal\" to do script'));assert.ok(!args[1].includes('front window'));await writeFile(join(dir,'rehearsal-result.json'),JSON.stringify({rehearsal:true,tty:true,liveRequests:0}),{mode:0o600});return Buffer.from('tab 1 of window id 123');}assert.ok(args[1].includes('close window id 123'));closed=true;return Buffer.alloc(0);}});assert.equal(result.liveRequests,0);assert.equal(closed,true);}finally{await rm(dir,{recursive:true,force:true});}
});

test('portable temporary directory is canonical, private and removed',async()=>{
 const {realpath,lstat}=await import('node:fs/promises');const dir=await privateTemporaryDirectory('exp710-portable-test-');
 try{assert.equal(await realpath(dir),dir);assert.equal((await lstat(dir)).mode&0o077,0);assert.equal(await claimRun(dir,identity),true);}
 finally{await rm(dir,{recursive:true,force:true});}
});

async function launchFixture(){
 const {writeFile}=await import('node:fs/promises');const {prepareObservedLauncher}=await import('./rollout-launch.mjs');
 const dir=await privateTemporaryDirectory('exp710-launch-plan-');await mkdir(join(dir,'portable_agent'),{mode:0o700});
 const pins={};for(const name of ['otto_readiness.py','run_otto_acceptance.py','otto_acceptance_operator.py','otto_acceptance.py','service_auth_check.py']){
  const bytes=Buffer.from('# SYNTHETIC inert source only\n');await writeFile(join(dir,'portable_agent',name),bytes,{mode:0o600});pins[name]=createHash('sha256').update(bytes).digest('hex');
 }
 const f=fixture();let reads=0;const get=f.api.get;f.api.get=async(...args)=>{reads++;return get(...args);};
 const options={authorization:{scope:'local-qualification',liveExecutionEnabled:false,approvedHead:identity.head,baselineWorker:PILOT.offWorker},identity,source:dir,python:'/usr/bin/python3',pins,output:join(dir,'receipt.json'),claimDirectory:dir,api:f.api,mode:'fixture',clock:()=>1054,watch:{...f.options,intervalMs:1,maxWaitMs:100}};
 return{...f,dir,options,prepareObservedLauncher,reads:()=>reads};
}
test('exact observer wires real pinned launcher arguments as nonexecutable data once',async()=>{
 const f=await launchFixture();try{
  const r=await f.prepareObservedLauncher(f.options);assert.equal(r.liveExecutionEnabled,false);assert.equal(r.plan.liveExecutionEnabled,false);assert.equal(r.independentlyRecheckRequired,true);
  assert.deepEqual(r.plan.args,['-m','portable_agent.run_otto_acceptance',String(identity.runId),identity.head,f.options.output]);assert.equal(r.proof.artifactId,42);
  const before=f.reads();await assert.rejects(f.prepareObservedLauncher(f.options),/Duplicate/);assert.equal(f.reads(),before);
 }finally{await rm(f.dir,{recursive:true,force:true});}
});
for(const patch of [{mode:'live'},{authorization:{scope:'live',liveExecutionEnabled:true}},{authorization:{scope:'local-qualification',liveExecutionEnabled:false,approvedHead:'b'.repeat(40),baselineWorker:PILOT.offWorker}}])test('launch capability and wrong head refused before observation',async()=>{
 const f=await launchFixture();try{await assert.rejects(f.prepareObservedLauncher({...f.options,...patch}),/qualification refused/);assert.equal(f.reads(),0);}finally{await rm(f.dir,{recursive:true,force:true});}
});
for(const now of [999,1121,1421])test(`planner stale/future/short window refuses ${now}`,async()=>{
 const f=await launchFixture();try{await assert.rejects(f.prepareObservedLauncher({...f.options,clock:()=>now}),/window refused/);}finally{await rm(f.dir,{recursive:true,force:true});}
});
test('historical receipt can only produce inert archive qualification',async()=>{
 const f=await launchFixture();f.run.status='completed';f.run.conclusion='success';try{
  const r=await f.prepareObservedLauncher({...f.options,mode:'historical',clock:()=>99999999,watch:{...f.options.watch,archive:false}});assert.equal(r.historical,true);assert.equal(r.liveExecutionEnabled,false);
 }finally{await rm(f.dir,{recursive:true,force:true});}
});
test('watch options cannot convert completed history into fresh proof',async()=>{
 const f=await launchFixture();f.run.status='completed';f.run.conclusion='success';try{await assert.rejects(f.prepareObservedLauncher({...f.options,watch:{...f.options.watch,archive:true}}));}finally{await rm(f.dir,{recursive:true,force:true});}
});

test('fixture executor rejects forged, historical and repeated capabilities before any Terminal',async()=>{
 const {executePrivateLauncherFixture}=await import('./rollout-launch.mjs');
 await assert.rejects(executePrivateLauncherFixture({qualificationOnly:true},'/unused'),/executor refused/);
 const f=await launchFixture();try{
  f.run.status='completed';f.run.conclusion='success';const history=await f.prepareObservedLauncher({...f.options,mode:'historical'});
  await assert.rejects(executePrivateLauncherFixture(history,f.dir),/executor refused/);
 }finally{await rm(f.dir,{recursive:true,force:true});}
 const g=await launchFixture();try{
  const prepared=await g.prepareObservedLauncher(g.options);
  await assert.rejects(executePrivateLauncherFixture(prepared,g.dir,{bundle:{rehearsalOnly:false}}),/inputs refused/);
  await assert.rejects(executePrivateLauncherFixture(prepared,g.dir),/executor refused/);
 }finally{await rm(g.dir,{recursive:true,force:true});}
});
