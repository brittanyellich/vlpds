import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,readdirSync,rmSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {projectOffConfig,offConfigReceipt} from '../scripts/off-config-projection.mjs';
import {checkProtectedOffConfig,OFF_CONFIG_CATEGORIES} from '../scripts/off-config-gates.mjs';
import {OFF_STAGE_CATEGORIES} from '../scripts/off-staging-transport.mjs';
const clean=()=>({vars:{AGENT_A2A_ENABLED:'false',AGENT_A2A_RUNTIME:'native-profile-v1'}});
const environment=()=>({GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'brittanyellich/vlpds',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_WORKFLOW:'Project protected OFF config (read only)',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:'a'.repeat(40),REVIEWED_HEAD:'a'.repeat(40),GITHUB_RUN_ID:'123456',DEPLOY_CONFIG:JSON.stringify(clean())});
test('projection uses exact shared gates and emits fixed labels without values',()=>{
 const cases=[['SECRET/not-json','protected-json'],[JSON.stringify({...clean(),keep_vars:true}),'protected-variable-policy'],[JSON.stringify({vars:{SECRET:'never-output'}}),'protected-agent-off-keys'],[JSON.stringify({vars:{AGENT_A2A_ENABLED:false,AGENT_A2A_RUNTIME:'native-profile-v1'}}),'protected-agent-off-enabled'],[JSON.stringify({vars:{AGENT_A2A_ENABLED:'false',AGENT_A2A_RUNTIME:'SECRET'}}),'protected-agent-off-runtime'],[JSON.stringify(clean()),null]];
 for(const [bytes,label] of cases){
  let active=null,passed=false;try{checkProtectedOffConfig(bytes,{onStage:s=>{active=s;}});passed=true;}catch{}
  const out=projectOffConfig(bytes);assert.deepEqual(out,{result:passed?'passed':'refused',failedStage:passed?null:active});assert.equal(out.failedStage,label);
  assert.ok(!JSON.stringify(out).includes('SECRET'));assert.deepEqual(Object.keys(out),['result','failedStage']);
 }
 assert.throws(()=>projectOffConfig(' '.repeat(1048577)),/^Error: OFF config projection refused$/);
 assert.throws(()=>projectOffConfig(undefined),/^Error: OFF config projection refused$/);
 for(const category of OFF_CONFIG_CATEGORIES)assert.ok(OFF_STAGE_CATEGORIES.includes(category));
});
test('receipt is exact context bound and never grants stage readiness',()=>{
 const e=environment(),r=offConfigReceipt(e);assert.equal(r.result,'passed');assert.equal(r.readOnly,true);assert.equal(r.readyForStage,false);assert.equal(r.head,e.GITHUB_SHA);
 for(const patch of [{GITHUB_ACTIONS:'false'},{GITHUB_REPOSITORY:'other/repo'},{GITHUB_REF:'refs/heads/other'},{GITHUB_EVENT_NAME:'push'},{GITHUB_WORKFLOW:'other'},{GITHUB_RUN_ATTEMPT:'2'},{REVIEWED_HEAD:'b'.repeat(40)},{GITHUB_SHA:'SECRET'},{GITHUB_RUN_ID:'0'}])assert.throws(()=>offConfigReceipt({...e,...patch}),/^Error: OFF config projection refused$/);
});
test('pure diagnostic has no provider imports or network/subprocess activity',()=>{
 const source=readFileSync(new URL('../scripts/off-config-projection.mjs',import.meta.url),'utf8');
 const imports=[...source.matchAll(/from '([^']+)'/g)].map(m=>m[1]);assert.deepEqual(imports,['node:fs','node:path','node:url','./off-config-gates.mjs']);
 const shared=readFileSync(new URL('../scripts/off-config-gates.mjs',import.meta.url),'utf8');assert.ok(!shared.includes('import '));
 const original=globalThis.fetch;let calls=0;globalThis.fetch=()=>{calls++;throw new Error('network prohibited');};try{offConfigReceipt(environment());assert.equal(calls,0);}finally{globalThis.fetch=original;}
});
test('CLI writes only one bounded receipt and refuses overwrite or invalid context',t=>{
 const dir=mkdtempSync(join(tmpdir(),'off-config-synthetic-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const cli=new URL('../scripts/off-config-projection.mjs',import.meta.url);
 const env={...environment(),RUNNER_TEMP:dir};const run=patch=>spawnSync(process.execPath,[cli.pathname],{env:{...env,...patch},encoding:'utf8'});
 const first=run({DEPLOY_CONFIG:JSON.stringify({vars:{SECRET:'value'}})});assert.equal(first.status,0);assert.equal(first.stdout,'');assert.equal(first.stderr,'');assert.deepEqual(readdirSync(dir),['exp710-off-config-projection.json']);
 const path=join(dir,'exp710-off-config-projection.json'),bytes=readFileSync(path);assert.ok(bytes.length<1024);assert.equal(statSync(path).mode&0o777,0o600);const receipt=JSON.parse(bytes);assert.equal(receipt.failedStage,'protected-agent-off-keys');assert.equal(receipt.readyForStage,false);assert.ok(!bytes.includes('SECRET'));assert.ok(!bytes.includes('value'));
 const second=run({});assert.equal(second.status,1);assert.equal(second.stderr.trim(),'OFF config projection refused');assert.deepEqual(readFileSync(path),bytes);
 const invalid=run({GITHUB_REF:'refs/heads/untrusted'});assert.equal(invalid.status,1);assert.equal(invalid.stderr.trim(),'OFF config projection refused');assert.deepEqual(readFileSync(path),bytes);
});
test('workflow is manual only and exposes only the approved config secret to projection',()=>{
 const w=readFileSync(new URL('../../../.github/workflows/cloudflare-off-config-projection.yml',import.meta.url),'utf8');
 assert.match(w,/workflow_dispatch:/);assert.ok(!/^  (push|pull_request|schedule):/m.test(w));
 const secrets=[...w.matchAll(/secrets\.([A-Z_]+)/g)].map(m=>m[1]);assert.deepEqual(secrets,['VLPDS_CLOUDFLARE_CONFIG_JSON']);
 assert.ok(!/CLOUDFLARE_API_TOKEN|DEPLOY_TOKEN|npm |wrangler|deployments:|actions: write/.test(w));assert.match(w,/github.run_attempt == 1/);assert.match(w,/persist-credentials: false/);assert.match(w,/REVIEWED_HEAD:/);
});
