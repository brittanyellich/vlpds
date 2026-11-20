import test from'node:test';import assert from'node:assert/strict';import{checkCandidateToken}from'../scripts/pilot-token-check.mjs';import{PILOT,normalizeCredentialMetadata}from'../scripts/pilot-activation-plan.mjs';
const now=1800000000,iso=n=>new Date(n*1000).toISOString();const selected={id:'synthetic_token_id',created_at:iso(now-10),expires_at:iso(now+890),max_expires_at:iso(now+3590),idle_ttl_seconds:900,profile_id:PILOT.profile,org_binding:'org',org_id:PILOT.org,scopes:['org:execute'],status:'active'};
const expected=normalizeCredentialMetadata(selected,{now,expectedOrg:PILOT.org}),raw={...selected,name:'synthetic',created_via:'cli',last_used_at:null,rotated_at:null,revoked_at:null};
test('same bearer self-introspection uses fixed auth API and exact scope/id/expiry; sliding idle allowed',async()=>{
 const result=await checkCandidateToken('kody_at_SYNTHETIC_ONLY',{expected,deadline:now+600,now,fetchImpl:async(url,r)=>{assert.equal(url,'https://api.kody.codes/v1/tokens/current');assert.equal(r.method,'GET');assert.equal(r.redirect,'error');assert.equal(r.headers.Authorization,'Bearer kody_at_SYNTHETIC_ONLY');return new Response(JSON.stringify({...raw,expires_at:iso(now+900)}),{headers:{'content-type':'application/json'}});}});assert.equal(result.id,expected.id);
});
test('wrong token metadata, wrappers, permissions, expiry and token-valued responses fail closed once',async()=>{
 for(const value of[{...raw,id:'other'},{...raw,scopes:['org:execute','secret:use']},{...raw,status:'revoked'},{...raw,org_id:'other'},{...raw,profile_id:'other'},{...raw,max_expires_at:iso(now+7200)},{data:raw},{...raw,token:'RAW_SECRET'}]){
 let count=0;await assert.rejects(checkCandidateToken('kody_at_SYNTHETIC_ONLY',{expected,deadline:now+600,now,fetchImpl:async()=>{count++;return new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});}}),/^Error: Candidate token introspection refused$/);assert.equal(count,1);
 }
});
