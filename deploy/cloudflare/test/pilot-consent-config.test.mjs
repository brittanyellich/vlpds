import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
// Synthetic pins replace only the fixed planning constants in this test module.
// Deployment preparation and configuration logic remain actual source.
const card='{"synthetic-consent-card":true}',account='a'.repeat(32),digest='sha256:'+'b'.repeat(64);
let source=readFileSync(new URL('../scripts/pilot-config.mjs',import.meta.url),'utf8');
assert.equal(source.split("import {PILOT} from './pilot-activation-plan.mjs';").length,2);
source=source.replace("import {PILOT} from './pilot-activation-plan.mjs';",`const PILOT=${JSON.stringify({digest,caller:'did:plc:syntheticcaller',cardKey:'zSynthetic',cardHash:createHash('sha256').update(card).digest('hex')})};`)
 .replace("from './prepare-deploy.mjs'",`from '${new URL('../scripts/prepare-deploy.mjs',import.meta.url).href}'`);
const {preparePilotConfig}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
function env(flag){return {CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:'synthetic',DEPLOY_TOKEN:'c'.repeat(64),DEPLOY_CONFIG:JSON.stringify({name:'crate-pds',account_id:account,main:'src/index.ts',vars:{ENABLED:'true',PUBLIC_HOST:'pds.crate.social',HANDLE_DOMAIN:'crate.social',S3_BUCKET:'crate-pds',S3_PREFIX:'crate',ADMIN_HOST:'admin.crate.social',...(flag===undefined?{}:{AGENT_A2A_REQUIRE_OWNER_CONSENT:flag})},containers:[{class_name:'Pds',scheduling_policy:'durable_object',images:{pds:{image:'synthetic'}}}],durable_objects:{bindings:[{name:'PDS',class_name:'Pds'}]},routes:[{pattern:'admin.crate.social/*'}]})};}

test('explicit required mode adds only active policy binding and removes it with lease on OFF',()=>{
 const active=preparePilotConfig(env(),card,true,1800000600,{ownerConsentRequired:true});
 assert.equal(active.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT,'true');assert.equal(active.vars.AGENT_A2A_ENABLED,'true');
 assert.equal(active.containers[0].images.pds.image,`registry.cloudflare.com/${account}/vlpds@${digest}`);
 const off=preparePilotConfig({...env(),DEPLOY_CONFIG:JSON.stringify({...JSON.parse(env().DEPLOY_CONFIG),vars:{...JSON.parse(env().DEPLOY_CONFIG).vars,...active.vars,AGENT_A2A_ENABLED:'false'}})},card,false,undefined,{ownerConsentRequired:true});
 assert.equal(off.vars.AGENT_A2A_ENABLED,'false');assert.equal(off.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT,undefined);assert.equal(off.vars.AGENT_A2A_EXPIRES_AT,undefined);
});
test('legacy remains absent; requested true cannot silently become legacy activation',()=>{
 assert.equal(preparePilotConfig(env(),card,true,1800000600).vars.AGENT_A2A_REQUIRE_OWNER_CONSENT,undefined);
 assert.throws(()=>preparePilotConfig(env('true'),card,true,1800000600));
 assert.equal(preparePilotConfig(env('true'),card,false).vars.AGENT_A2A_REQUIRE_OWNER_CONSENT,undefined);
 for(const flag of ['TRUE',true,null])assert.throws(()=>preparePilotConfig(env(flag),card,false));
 for(const ownerConsentRequired of ['true',null,1])assert.throws(()=>preparePilotConfig(env(),card,true,1800000600,{ownerConsentRequired}));
});
