import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';
import{preflightDiagnostic}from'../scripts/pilot-preflight-diagnostic.mjs';import{preflightInputs}from'../scripts/pilot-preflight-inputs.mjs';import{PILOT}from'../scripts/pilot-activation-plan.mjs';
const pairs=[["ADMIN_HOST","plain_text"],["ADMIN_TOKEN","secret_text"],["AGENT_A2A_ENABLED","plain_text"],["AGENT_A2A_RUNTIME","plain_text"],["CF_ACCOUNT_ID","secret_text"],["DEPLOY_TOKEN","secret_text"],["EMAIL_API_TOKEN","secret_text"],["EMAIL_API_URL","secret_text"],["EMAIL_FROM_ADDRESS","secret_text"],["ENABLED","plain_text"],["HANDLE_DOMAIN","plain_text"],["INTERNAL_TOKEN","secret_text"],["JWT_SECRET","secret_text"],["KEK","secret_text"],["OPERATOR_DID","plain_text"],["PDS","durable_object_namespace"],["PLC_RECOVERY_DID_KEY","secret_text"],["PLC_ROTATION_KEY_HEX","secret_text"],["PUBLIC_HOST","plain_text"],["S3_ACCESS_KEY","secret_text"],["S3_BUCKET","plain_text"],["S3_PREFIX","plain_text"],["S3_SECRET_KEY","secret_text"]];
const env={CLOUDFLARE_ACCOUNT_ID:'a'.repeat(32),CLOUDFLARE_API_TOKEN:'c'.repeat(40),VLPDS_DEPLOY_TOKEN:'d'.repeat(64)};
const deps={inputs:(_e,_m,report)=>{report({stage:'execution-context',ok:true});return{identity:{repository:'brittanyellich/vlpds',runId:123,head:'b'.repeat(40)},card:'synthetic'};},configuration:()=>({})};
function network(scenario,calls){return async(url,r)=>{
 calls.push([url,r.method]);assert.equal(r.method,'GET');
 const json=(v,type='application/json')=>new Response(JSON.stringify(v),{headers:{'content-type':type}});
 if(url.includes('/_deploy/status'))return json({desired:`registry.cloudflare.com/${env.CLOUDFLARE_ACCOUNT_ID}/vlpds@${PILOT.digest}`,current:scenario==='status'?'RAW_SECRET_DO_NOT_ECHO':`registry.cloudflare.com/${env.CLOUDFLARE_ACCOUNT_ID}/vlpds@${PILOT.digest}`,running:true,extra:'RAW_SECRET_DO_NOT_ECHO'});
 if(url.startsWith('https://plc.directory/')){const did='did:plc:6tlvgafuonoighfrtpejff5m';return json({id:scenario==='key'?'wrong':did,verificationMethod:[{id:did+'#card-signing',type:'Multikey',controller:did,publicKeyMultibase:PILOT.cardKey}],service:[{id:'#atproto_pds',type:'AtprotoPersonalDataServer',serviceEndpoint:'https://pds.crate.social'}]},'application/did+ld+json; charset=utf-8');}
 if(url.endsWith('/deployments'))return json({success:true,result:{deployments:[{versions:[{version_id:scenario==='worker'?'00000000-0000-0000-0000-000000000000':PILOT.offWorker,percentage:100}]}]}});
 if(url.includes('/versions/'))return json({success:true,result:{id:url.split('/').at(-1),resources:{script:{etag:'e'.repeat(64)},bindings:pairs.map(([name,type])=>({name,type,...(type==='plain_text'?{text:name==='AGENT_A2A_ENABLED'?'false':name==='AGENT_A2A_RUNTIME'?'native-profile-v1':'synthetic'}:{})}))}}});
 if(url.endsWith('/xrpc/_health'))return json({version:'synthetic'});
 if(url.endsWith('/account/spaces'))return new Response('<script src="/assets/index-D5JRYEyV.js"></script>',{headers:{'content-type':'text/html'}});
 return new Response('not found',{status:scenario==='card'?200:404});
};}
test('GET-only diagnostic emits masked qualified state, accepts observed DID type and never authorizes pilot',async()=>{
 const calls=[],r=await preflightDiagnostic(env,network('ok',calls),deps);assert.equal(r.result,'passed');assert.equal(r.readOnly,true);assert.equal(r.readyForPilot,false);assert.equal(r.credentialProof,'not-attempted');assert.equal(r.didMediaType,'application/did+ld+json');assert.ok(calls.every(([,method])=>method==='GET'));
 assert.ok(!JSON.stringify(r).includes(env.CLOUDFLARE_ACCOUNT_ID));assert.ok(!JSON.stringify(r).includes('RAW_SECRET_DO_NOT_ECHO'));
});
test('status, key, worker and Card mismatches produce fixed failure stages without raw response data',async()=>{
 for(const [scenario,stage]of[['status','qualified-runtime-status'],['key','current-card-authority'],['worker','off-worker-bindings'],['card','public-health-ui-card-off']]){const r=await preflightDiagnostic(env,network(scenario,[]),deps);assert.equal(r.result,'failed');assert.ok(r.checks.some(x=>x.stage===stage&&x.ok===false));assert.ok(!JSON.stringify(r).includes('RAW_SECRET_DO_NOT_ECHO'));}
});
test('pilot secrets are refused before any diagnostic network call',async()=>{
 let calls=0;const r=await preflightDiagnostic({...env,VLPDS_AGENT_KODY_TOKEN:'NEVER_ECHO'},async()=>{calls++;},deps);assert.equal(r.result,'failed');assert.equal(calls,0);assert.ok(!JSON.stringify(r).includes('NEVER_ECHO'));
});
test('shared local gate reports fixed stage/hash only for invalid Card input',()=>{
 const rows=[];assert.throws(()=>preflightInputs({GITHUB_REPOSITORY:'brittanyellich/vlpds',GITHUB_REF:'refs/heads/main',GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'123',GITHUB_SHA:'b'.repeat(40),RUNNER_TEMP:'/home/runner/work/_temp',PILOT_CARD_JSON:'SECRET_NOT_A_CARD'},'diagnose',x=>rows.push(x)));
 assert.equal(rows.at(-1).stage,'signed-card-input');assert.equal(rows.at(-1).ok,false);assert.ok(!JSON.stringify(rows).includes('SECRET_NOT_A_CARD'));
});
test('diagnostic workflow has only existing bindings, no install/build/mint/deploy/restart or pilot secrets',()=>{
 const w=readFileSync(new URL('../../../.github/workflows/cloudflare-pilot-diagnostic.yml',import.meta.url),'utf8');assert.match(w,/workflow_dispatch:/);assert.match(w,/github.ref == 'refs\/heads\/main'/);assert.match(w,/persist-credentials: false/);assert.ok(!/VLPDS_AGENT_KODY_TOKEN|VLPDS_AGENT_BRIDGE_KEY|npm ci|wrangler |docker |pilot-runner\.mjs/.test(w));assert.equal((w.match(/\$\{\{ secrets\./g)||[]).length,4);
});
