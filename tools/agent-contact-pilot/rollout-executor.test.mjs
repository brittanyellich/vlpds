// Explicit local GUI fixture only; default CI never opens a Terminal window.
import test from'node:test';import assert from'node:assert/strict';
import{readFile,rm}from'node:fs/promises';
import{privateTemporaryDirectory}from'./rollout-private-temp.mjs';
import{integratedFixture}from'./rollout-integrated-fixture.mjs';
const enabled=process.env.EXP710_TERMINAL_FIXTURE==='1'&&Boolean(process.env.EXP710_REHEARSAL_SETUP&&process.env.EXP710_REHEARSAL_PYTHON);
for(const action of ['input','timeout','stop'])test(`owned private executor ${action}`,{skip:!enabled},async()=>{
 const setup=JSON.parse(await readFile(process.env.EXP710_REHEARSAL_SETUP));const claims=await privateTemporaryDirectory('exp710-executor-test-');
 try{
  const r=await integratedFixture({...setup,python:process.env.EXP710_REHEARSAL_PYTHON,claimDirectory:claims,identity:{runId:45063222759,head:'5eb6672f161aa5c3b1a666cf2118690843c40227'},scenario:'executor-'+action,terminalApp:true});
  assert.equal(r.result,action==='input'?'synthetic-complete':'refused');assert.equal(r.liveRequests,0);assert.equal(r.realPrompt,false);assert.equal(r.duplicateExecutorRefused,true);
  assert.equal(r.tty.cliMainExercised,true);assert.equal(r.tty.networkProbeDenied,true);assert.equal(r.tty.ownedWindowClosed,true);
  assert.equal(r.tty.privateInput.echoDisabled,true);assert.equal(r.tty.privateInput.echoRestored,true);assert.equal(r.cleanupAttempted,true);assert.equal(r.syntheticCleanupVerified,true);
  assert.equal(r.tty.counts.mockLogin,action==='input'?1:0);assert.equal(r.tty.counts.mockRequests,action==='input'?2:0);
  assert.equal(r.tty.privateInput.inputMatched,action==='input');assert.equal(r.tty.privateInput.timedOut,action==='timeout');assert.equal(r.tty.privateInput.stopped,action==='stop');
 }finally{await rm(claims,{recursive:true,force:true});}
});
