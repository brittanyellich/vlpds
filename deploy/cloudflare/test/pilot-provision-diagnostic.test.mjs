import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import {provisionDiagnostic} from '../scripts/pilot-provision-diagnostic.mjs';import {CandidateTokenRefused} from '../scripts/pilot-token-check.mjs';
const identity={repository:'brittanyellich/vlpds',runId:123,head:'a'.repeat(40),workerQualificationSha256:'b'.repeat(64)};
test('provision receipt uses only fixed codes, never raw errors or credentials',()=>{
 let output;const report=provisionDiagnostic(identity,s=>output=s);
 report('load-private-state','started');report('load-private-state','passed');report('candidate-introspection','started');report('candidate-introspection','failed',Object.assign(new CandidateTokenRefused('candidate-http'),{body:'PRIVATE_DATA',token:'PRIVATE_DATA'}));
 const r=JSON.parse(output);assert.equal(r.readyForPilot,false);assert.deepEqual(r.steps,[{stage:'load-private-state',status:'passed'},{stage:'candidate-introspection',status:'failed',candidateStage:'candidate-http'}]);assert.ok(!output.includes('PRIVATE_DATA'));
 assert.throws(()=>report('PRIVATE_DATA','failed'));assert.throws(()=>report('candidate-introspection','PRIVATE_DATA'));
});
test('arbitrary exception properties are never diagnostic data',()=>{
 let output;const report=provisionDiagnostic(identity,s=>output=s);report('transfer-two-bindings','started');report('transfer-two-bindings','failed',{stage:'PRIVATE_DATA',message:'PRIVATE_DATA'});assert.ok(!output.includes('PRIVATE_DATA'));assert.ok(!output.includes('candidateStage'));
});
test('failure-only upload keeps successful Otto ready artifact unique and has no secret env',()=>{
 const source=readFileSync(new URL('../../../.github/workflows/cloudflare-agent-pilot.yml',import.meta.url),'utf8');const start=source.indexOf('      - name: Retain sanitized provisioning stages'),end=source.indexOf('      - name: Activate guarded Otto-only pilot',start);const step=source.slice(start,end);
 assert.ok(start>0&&end>start);assert.match(step,/if: failure\(\)/);assert.match(step,/exp710-provision-diagnostic.json/);assert.ok(!step.includes('secrets.')&&!step.includes('env:'));
});

test('diagnostic identity refuses extra fields rather than copying private state',()=>{
 assert.throws(()=>provisionDiagnostic({...identity,token:'PRIVATE_DATA'},()=>{}));
});
