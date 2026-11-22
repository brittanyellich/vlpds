import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {projectStrategy,strategyReceipt} from '../scripts/pilot-strategy-projection.mjs';
const config=s=>JSON.stringify({durable_objects:{code_update_strategy:s}});
test('projection assumptions match pinned publisher',()=>{
 const pkg=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8'));
 assert.equal(pkg.devDependencies.wrangler,'4.158.0');
 const publisher=readFileSync(new URL('../scripts/pilot-publish.mjs',import.meta.url),'utf8');
 assert.ok(publisher.includes("'--durable-objects-code-update-mode',PILOT_UPDATE_MODE"));
});
test('pinned Wrangler default and config selection',()=>{
 assert.deepEqual(projectStrategy('{}'),{source:'wrangler-default',mode:'deferred',maxDelaySeconds:300});
 assert.deepEqual(projectStrategy(config({mode:'deferred'})),{source:'config',mode:'deferred',maxDelaySeconds:300});
 for(const delay of [0,0.001,120,86400])assert.equal(projectStrategy(config({mode:'deferred',max_delay:delay})).maxDelaySeconds,delay);
 assert.deepEqual(projectStrategy(config({mode:'immediate',max_delay:60})),{source:'config',mode:'immediate',maxDelaySeconds:null});
});
test('CLI replaces entire configured strategy without inheriting delay',()=>{
 assert.deepEqual(projectStrategy(config({mode:'deferred',max_delay:120}),{cliMode:{mode:'deferred'}}),{source:'cli',mode:'deferred',maxDelaySeconds:300});
 assert.equal(projectStrategy(config({mode:'deferred'}),{cliMode:{mode:'immediate'}}).mode,'immediate');
});
test('malformed and unsupported inputs refuse without reflection',()=>{
 for(const bytes of ['SENSITIVE','null','[]',JSON.stringify({durable_objects:[]}),config(null),config({mode:'SENSITIVE'}),config({mode:'deferred',secret:'SENSITIVE'}),...[-1,86401,0.0001,'SENSITIVE',null].flatMap(max_delay=>['deferred','immediate'].map(mode=>config({mode,max_delay}))), ' '.repeat(1048577)]){
  assert.throws(()=>projectStrategy(bytes),e=>e.message==='Strategy projection refused');
 }
});
const env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'brittanyellich/vlpds',GITHUB_REF:'refs/heads/main',GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1',DEPLOY_CONFIG:JSON.stringify({vars:{SECRET:'SENSITIVE'},account_id:'SENSITIVE',durable_objects:{code_update_strategy:{mode:'deferred',max_delay:120}}})};
test('receipt allowlists fields and never emits unrelated sensitive fields',()=>{
 const receipt=strategyReceipt(env);
 assert.deepEqual(Object.keys(receipt).sort(),['version','kind','readOnly','repo','head','runId','runAttempt','wranglerVersion','source','mode','maxDelaySeconds'].sort());
 assert.equal(JSON.stringify(receipt).includes('SENSITIVE'),false);
 assert.equal(receipt.maxDelaySeconds,null);
 assert.equal(receipt.mode,'immediate');assert.equal(receipt.source,'cli');
 for(const [key,value] of [['GITHUB_REPOSITORY','other/repo'],['GITHUB_REF','refs/heads/other'],['GITHUB_SHA','bad'],['GITHUB_RUN_ATTEMPT','2'],['GITHUB_RUN_ID','bad']])assert.throws(()=>strategyReceipt({...env,[key]:value}),/Strategy projection refused/);
});
