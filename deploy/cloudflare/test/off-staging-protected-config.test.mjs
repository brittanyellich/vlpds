import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {prepareOffStageConfig,prepareOffStage,offImage,OFF_STAGE as P} from '../scripts/off-staging-plan.mjs';
import {createOffDiagnostics} from '../scripts/off-staging-transport.mjs';
const account='a'.repeat(32);
const config=()=>({name:'crate-pds',account_id:account,main:'../src/index.ts',vars:{ENABLED:'true',PUBLIC_HOST:'pds.crate.social',HANDLE_DOMAIN:'crate.social',S3_BUCKET:'crate-pds',S3_PREFIX:'crate',ADMIN_HOST:'admin.crate.social',AGENT_A2A_ENABLED:'false',AGENT_A2A_RUNTIME:'native-profile-v1'},containers:[{class_name:'Pds',scheduling_policy:'durable_object',images:{pds:{image:offImage(account,P.rollback)}}}],durable_objects:{bindings:[{name:'PDS',class_name:'Pds'}]},routes:[{pattern:'admin.crate.social/*'}]});
const env=c=>({DEPLOY_CONFIG:JSON.stringify(c),CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:'synthetic',DEPLOY_TOKEN:'a'.repeat(64)});
test('protected config subdiagnostics distinguish synthetic refusals without retaining values',()=>{
 const cases=[['protected-json',()=>({...env(config()),DEPLOY_CONFIG:'SECRET/not-json'})],['protected-variable-policy',()=>env({...config(),keep_vars:true})],['protected-agent-off',()=>{const c=config();c.vars.AGENT_A2A_RUNTIME='SECRET';return env(c);}],['protected-deployment-contract',()=>{const c=config();c.vars.PUBLIC_HOST='SECRET';return env(c);}]];
 for(const [stage,input] of cases){const d=createOffDiagnostics();assert.throws(()=>prepareOffStageConfig(input(),{onStage:d.mark}));d.capture();assert.deepEqual(d.snapshot(),{version:1,failedStage:stage});d.mark('provider-execution');d.capture();assert.equal(d.snapshot().failedStage,stage);assert.ok(!JSON.stringify(d.snapshot()).includes('SECRET'));}
});
test('account boundary remains bound and diagnostic observer preserves successful projection',()=>{
 const d=createOffDiagnostics();assert.throws(()=>prepareOffStage(env(config()),{onStage:d.mark}));d.capture();assert.equal(d.snapshot().failedStage,'protected-account');
 const clean=createOffDiagnostics(),input=env(config());assert.deepEqual(prepareOffStageConfig(input,{onStage:clean.mark}),prepareOffStageConfig(input));assert.deepEqual(clean.snapshot(),{version:1,failedStage:null});
});

test('OFF workflow uses the established protected JSON input contract with no legacy fallback',()=>{
 const workflow=readFileSync(new URL('../../../.github/workflows/cloudflare-off-staging.yml',import.meta.url),'utf8');
 const established=readFileSync(new URL('../../../.github/workflows/cloudflare-deploy.yml',import.meta.url),'utf8');
 const binding='DEPLOY_CONFIG: ${{ secrets.VLPDS_CLOUDFLARE_CONFIG_JSON }}';
 assert.ok(established.includes(binding));assert.equal(workflow.split(binding).length-1,1);assert.ok(!workflow.includes('secrets.DEPLOY_CONFIG'));
 const syntheticSecret=JSON.stringify(config());const input={...env(config()),DEPLOY_CONFIG:syntheticSecret};assert.equal(prepareOffStageConfig(input).vars.AGENT_A2A_ENABLED,'false');
 const d=createOffDiagnostics();assert.throws(()=>prepareOffStageConfig({...input,DEPLOY_CONFIG:''},{onStage:d.mark}));d.capture();assert.deepEqual(d.snapshot(),{version:1,failedStage:'protected-json'});
});
