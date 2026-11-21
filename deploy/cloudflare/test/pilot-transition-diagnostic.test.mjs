import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import {transitionDiagnostic,transitionReason} from '../scripts/pilot-transition-diagnostic.mjs';import {ProviderPending} from '../scripts/pilot-provider.mjs';
const identity={repository:'brittanyellich/vlpds',runId:123,head:'a'.repeat(40),workerQualificationSha256:'b'.repeat(64)};
test('transition timings and reason codes exclude arbitrary input and errors',()=>{
 let output,t=0;const report=transitionDiagnostic('activate',identity,s=>output=s,()=>t);
 report('runtime-restart','started');t=75000;report('runtime-restart','failed',{reason:transitionReason(new ProviderPending('Provider unavailable')),body:'PRIVATE_DATA'});
 const r=JSON.parse(output);assert.equal(r.readyForPilot,false);assert.deepEqual(r.steps,[{stage:'runtime-restart',status:'failed',startedMs:0,completedMs:75000,durationMs:75000,reason:'request-unavailable'}]);assert.ok(!output.includes('PRIVATE_DATA'));
 assert.equal(transitionReason(new ProviderPending('PRIVATE_DATA')),'provider-pending');assert.equal(transitionReason(new Error('PRIVATE_DATA')),'gate-refused');
 assert.throws(()=>report('PRIVATE_DATA','failed'));assert.throws(()=>transitionDiagnostic('activate',{...identity,token:'PRIVATE_DATA'},()=>{}));
});
test('readiness observations are bounded and code-allowlisted',()=>{
 let output;const report=transitionDiagnostic('activate',identity,s=>output=s,()=>0);report('readiness','started');
 for(let i=1;i<=20;i++)report('readiness-poll',i===20?'failed':'pending',{attempt:i,check:'public-checks',reason:'card-pending',raw:'PRIVATE_DATA'});
 report('readiness','failed',{reason:'gate-refused'});assert.equal(JSON.parse(output).polls.length,20);assert.ok(!output.includes('PRIVATE_DATA'));
 assert.throws(()=>report('readiness-poll','pending',{attempt:21,check:'public-checks',reason:'card-pending'}));
});
test('diagnostic clock going backward fails closed',()=>{let t=1;const report=transitionDiagnostic('disable',identity,()=>{},()=>t);t=0;assert.throws(()=>report('load-state','started'));});
test('failure-only transition uploads preserve successful single ready artifact and no upload secret env',()=>{
 const w=readFileSync(new URL('../../../.github/workflows/cloudflare-agent-pilot.yml',import.meta.url),'utf8');
 for(const [name,condition,path]of[['Retain sanitized activation failure stages',"failure() && steps.activate.outcome == 'failure'",'activate'],['Retain sanitized OFF failure stages',"always() && steps.disable.outcome == 'failure'",'disable']]){
  const start=w.indexOf('      - name: '+name),end=w.indexOf('\n      - name:',start+10),s=w.slice(start,end);assert.ok(start>0);assert.ok(s.includes('if: '+condition));assert.ok(s.includes('exp710-'+path+'-diagnostic.json'));assert.ok(!s.includes('secrets.')&&!s.includes('env:'));
 }
});
test('failed diagnostic sink is disabled once and cannot interrupt OFF',async()=>{
 const {bestEffortTransition}=await import('../scripts/pilot-transition-diagnostic.mjs');let calls=0,notices=0;
 const report=bestEffortTransition(()=>{calls++;throw new Error('PRIVATE_DATA');},()=>{notices++;});
 assert.doesNotThrow(()=>report('load-state','started'));assert.doesNotThrow(()=>report('runtime-restart','started'));assert.equal(calls,1);assert.equal(notices,1);
});
test('diagnostic initialization failure is also best-effort',async()=>{
 const {createTransitionReporter}=await import('../scripts/pilot-transition-diagnostic.mjs');let notices=0;
 const report=createTransitionReporter('disable',{...identity,runId:0},()=>{},()=>notices++);
 assert.doesNotThrow(()=>report('load-state','started'));assert.equal(notices,1);
});
