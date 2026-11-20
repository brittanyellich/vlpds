import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {activationPlan,transferSecrets,PILOT,normalizeCredentialMetadata} from '../scripts/pilot-activation-plan.mjs';

test('planning seam has no live transport or environment access',()=>{
 const source=readFileSync(new URL('../scripts/pilot-activation-plan.mjs',import.meta.url),'utf8');
 assert.ok(!/from ['"]node:(?:fs|child_process|https|http)|process\.|fetch\(/.test(source));
});
test('synthetic or drifted artifact/card evidence cannot yield activation plan',()=>{
 const now=1000, account='a'.repeat(32),image=`registry.cloudflare.com/${account}/vlpds@${PILOT.digest}`;
 const evidence={checkedAt:now,desired:image,current:image,running:true,runtime:'native-profile-v1',revision:PILOT.revision,
 platform:'linux/amd64',workerVersion:PILOT.offWorker,enabled:false,agentSecretBindings:0,
 publicChecks:{health:200,ui:200,card:404},cardCurrentKey:PILOT.cardKey,cardSignatureVerified:true,cardSha256:PILOT.cardHash};
 // These are explicitly synthetic evidence assertions, not authenticated receipts.
 const planned=activationPlan({account,now,evidence});assert.equal(planned.executable,false);
 assert.equal(planned.rollback.image,image);assert.equal(planned.tokenRequest.max_lifetime_seconds,3600);
 // Each independently corrupted prerequisite fails closed.
 for(const patch of [{cardSha256:'bad'},{checkedAt:0},{current:image+'x'},{enabled:true},{running:false},{agentSecretBindings:1},
 {platform:'linux/arm64'},{revision:'0'.repeat(40)},{workerVersion:'other'},{cardSignatureVerified:false},
 {publicChecks:{health:200,ui:200,card:200}}]) assert.throws(()=>activationPlan({account,now,evidence:{...evidence,...patch}}),/gate refused/);
});
test('secret transport gets only fixed stdin keys, fixed args and isolated CF env; buffer wiped',async()=>{
 let retained;const bridgeKey='b'.repeat(64),profileToken='kody_at_SYNTHETIC_ONLY',cloudflareToken='c'.repeat(40);
 const result=await transferSecrets({bridgeKey,profileToken,cloudflareToken,account:'a'.repeat(32)},async x=>{
 retained=x.stdin;assert.deepEqual(JSON.parse(x.stdin),{AGENT_A2A_BRIDGE_KEY:bridgeKey,AGENT_A2A_KODY_TOKEN:profileToken});
 assert.deepEqual(x.args,['secret','bulk','--name','crate-pds']);assert.deepEqual(Object.keys(x.childEnv).sort(),['CLOUDFLARE_ACCOUNT_ID','CLOUDFLARE_API_TOKEN']);
 assert.ok(!JSON.stringify(x.args).includes(profileToken));return true;
 });
 assert.deepEqual(result.names,['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN']);assert.ok(retained.every(v=>v===0));assert.ok(!JSON.stringify(result).includes(profileToken));
});
test('ambiguous, negative and exception transfers never retry or expose raw errors',async()=>{
 for(const outcome of [false,'true','throw']) {let calls=0,retained;
 await assert.rejects(transferSecrets({bridgeKey:'b'.repeat(64),profileToken:'kody_at_SYNTHETIC_ONLY',cloudflareToken:'c'.repeat(40),account:'a'.repeat(32)},async x=>{
 calls++;retained=x.stdin;if(outcome==='throw')throw new Error('SECRET_RAW_OUTPUT');return outcome;
 }),/^Error: Pilot secret transfer failed; do not retry automatically$/);
 assert.equal(calls,1);assert.ok(retained.every(v=>v===0));}
});

test('opaque Kody IDs and ISO metadata normalize with exact org/profile/caps; value is refused',()=>{
 const now=1800000000,iso=n=>new Date(n*1000).toISOString();
 const raw={id:'5wzk8hmass2hzbkapwl7',created_at:iso(now-10),expires_at:iso(now+890),max_expires_at:iso(now+3590),idle_ttl_seconds:900,profile_id:PILOT.profile,org_binding:'org',org_id:PILOT.org,scopes:['org:execute'],status:'active'};
 const normalized=normalizeCredentialMetadata(raw,{now,expectedOrg:PILOT.org});assert.equal(normalized.id,raw.id);assert.equal(normalized.issuedAt,now-10);
 for(const patch of [{token:'NEVER_ACCEPT'},{status:'revoked'},{org_id:'other'},{scopes:['org:execute','secret:use']},{max_expires_at:iso(now+7200)},{created_at:iso(now-601)},{expires_at:iso(now-1)},{id:''}])assert.throws(()=>normalizeCredentialMetadata({...raw,...patch},{now,expectedOrg:PILOT.org}));
});
