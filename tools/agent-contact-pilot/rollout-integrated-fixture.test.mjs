import test from 'node:test';import assert from 'node:assert/strict';
import{readFile,mkdtemp,rm}from'node:fs/promises';
import{integratedFixture}from'./rollout-integrated-fixture.mjs';
import{rehearseRolloutLaunch}from'./rollout-rehearse.mjs';
import{PILOT}from'../../deploy/cloudflare/scripts/pilot-activation-plan.mjs';
const configured=Boolean(process.env.EXP710_REHEARSAL_SETUP&&process.env.EXP710_REHEARSAL_PYTHON);
const identity={runId:45063222759,head:'5eb6672f161aa5c3b1a666cf2118690843c40227'};
for(const scenario of ['delay54','stale','missing','wrong-run','invalid-signature','unlock-timeout','request-timeout','short-lease','cleanup-failure','age120','age121','lease180','lease179'])test(`integrated inert consumer ${scenario}`,{skip:!configured},async()=>{
 const setup=JSON.parse(await readFile(process.env.EXP710_REHEARSAL_SETUP));const claimDirectory=await mkdtemp('/private/tmp/exp710-integration-test-');
 try{
  const result=await integratedFixture({...setup,identity,python:process.env.EXP710_REHEARSAL_PYTHON,claimDirectory,scenario});
  const success=['delay54','age120','lease180'].includes(scenario);assert.equal(result.result,success?'synthetic-complete':'refused');assert.equal(result.liveRequests,0);assert.equal(result.realPrompt,false);
  if(result.tty){assert.equal(result.tty.networkProbeDenied,true);assert.equal(result.tty.tty,true);if(success)assert.equal(result.tty.counts.mockRequests,2);}
  if(['stale','invalid-signature','short-lease','age121','lease179'].includes(scenario))assert.equal(result.tty.counts.prompt,0);
  if(scenario==='unlock-timeout')assert.equal(result.tty.counts.mockLogin,0);
  if(scenario==='request-timeout')assert.equal(result.tty.counts.mockRequests,1);
  if(scenario==='cleanup-failure'){assert.equal(result.cleanupAttempted,true);assert.equal(result.syntheticCleanupVerified,false);assert.equal(result.tty.acceptedSynthetic,true);assert.ok(result.timing.some(x=>x.phase==='synthetic-cleanup'));}
  if(success){const again=await integratedFixture({...setup,identity,python:process.env.EXP710_REHEARSAL_PYTHON,claimDirectory,scenario});assert.equal(again.result,'duplicate-refused');}
 }finally{await rm(claimDirectory,{recursive:true,force:true});}
});

test('unqualified interpreter cannot run fixture', {skip:!configured},async()=>{const setup=JSON.parse(await readFile(process.env.EXP710_REHEARSAL_SETUP));const claimDirectory=await mkdtemp('/private/tmp/exp710-bad-runtime-');try{const result=await integratedFixture({...setup,fixturePins:{...setup.fixturePins,interpreterSha256:'0'.repeat(64)},identity,python:process.env.EXP710_REHEARSAL_PYTHON,claimDirectory});assert.equal(result.result,'refused');assert.equal(result.failedPhase,'policy-consumer-private-terminal');assert.equal(result.tty,undefined);}finally{await rm(claimDirectory,{recursive:true,force:true});}});

test('rollout-owned entry refuses live mode, wrong approved head and baseline before adapters',async()=>{
 const good={mode:'fixture-only',approvedHead:identity.head,baselineWorker:PILOT.offWorker,liveExecutionEnabled:false,identity};
 for(const patch of [{mode:'live'},{approvedHead:'0'.repeat(40)},{baselineWorker:'old-worker'},{liveExecutionEnabled:true}])
  await assert.rejects(rehearseRolloutLaunch({...good,...patch}),/qualification refused/);
});
test('rollout-owned pinned integration launches once and remains inert',{skip:!configured},async()=>{
 const setup=JSON.parse(await readFile(process.env.EXP710_REHEARSAL_SETUP));const claimDirectory=await mkdtemp('/private/tmp/exp710-owned-launch-');
 try{
  const options={...setup,identity,python:process.env.EXP710_REHEARSAL_PYTHON,claimDirectory,mode:'fixture-only',approvedHead:identity.head,baselineWorker:PILOT.offWorker,liveExecutionEnabled:false};
  const result=await rehearseRolloutLaunch(options);assert.equal(result.result,'synthetic-complete');assert.equal(result.launcherPlanVerified,true);assert.equal(result.liveExecutionEnabled,false);assert.equal(result.liveRequests,0);
  assert.equal((await rehearseRolloutLaunch(options)).result,'duplicate-refused');
 }finally{await rm(claimDirectory,{recursive:true,force:true});}
});

test('unqualified fixture worker refuses before TTY execution',{skip:!configured},async()=>{
 const setup=JSON.parse(await readFile(process.env.EXP710_REHEARSAL_SETUP));const claimDirectory=await mkdtemp('/private/tmp/exp710-bad-worker-');
 try{const result=await integratedFixture({...setup,fixturePins:{...setup.fixturePins,'consumer-fixture-worker.py':'0'.repeat(64)},identity,python:process.env.EXP710_REHEARSAL_PYTHON,claimDirectory});assert.equal(result.result,'refused');assert.equal(result.tty,undefined);assert.equal(result.failedPhase,'policy-consumer-private-terminal');}
 finally{await rm(claimDirectory,{recursive:true,force:true});}
});
