import test from'node:test';import assert from'node:assert/strict';import{checkCandidateToken}from'../scripts/pilot-token-check.mjs';import{PILOT,normalizeCredentialMetadata}from'../scripts/pilot-activation-plan.mjs';
const now=1800000000,iso=n=>new Date(n*1000).toISOString();const selected={id:'synthetic_token_id',created_at:iso(now-10),expires_at:iso(now+890),max_expires_at:iso(now+3590),idle_ttl_seconds:900,profile_id:PILOT.profile,org_binding:'org',org_id:PILOT.org,scopes:['org:execute'],status:'active'};
const expected=normalizeCredentialMetadata(selected,{now,expectedOrg:PILOT.org}),raw={...selected,name:'synthetic',created_via:'cli',last_used_at:null,rotated_at:null,revoked_at:null};
test('same bearer self-introspection uses fixed auth API and exact scope/id/expiry; sliding idle allowed',async()=>{
 const result=await checkCandidateToken('kody_at_SYNTHETIC_ONLY',{expected,deadline:now+600,now,clock:()=>now,fetchImpl:async(url,r)=>{assert.equal(url,'https://api.kody.codes/v1/tokens/current');assert.equal(r.method,'GET');assert.equal(r.redirect,'error');assert.equal(r.headers.Authorization,'Bearer kody_at_SYNTHETIC_ONLY');return new Response(JSON.stringify({...raw,expires_at:iso(now+900)}),{headers:{'content-type':'application/json'}});}});assert.equal(result.id,expected.id);
});
test('wrong token metadata, wrappers, permissions, expiry and token-valued responses fail closed once',async()=>{
 for(const value of[{...raw,id:'other'},{...raw,scopes:['org:execute','secret:use']},{...raw,status:'revoked'},{...raw,org_id:'other'},{...raw,profile_id:'other'},{...raw,max_expires_at:iso(now+7200)},{data:raw},{...raw,token:'RAW_SECRET'}]){
 let count=0;await assert.rejects(checkCandidateToken('kody_at_SYNTHETIC_ONLY',{expected,deadline:now+600,now,clock:()=>now,fetchImpl:async()=>{count++;return new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});}}),/^Error: Candidate token introspection refused$/);assert.equal(count,1);
 }
});

test('response crossing a second validates sliding idle at completion time',async()=>{
 const advanced=now+1,selectedAfter={...selected,expires_at:iso(advanced+900)};
 assert.throws(()=>normalizeCredentialMetadata(selectedAfter,{now,expectedOrg:PILOT.org})); // Old deterministic failure.
 const result=await checkCandidateToken('kody_at_SYNTHETIC_ONLY',{expected,deadline:now+600,now,clock:()=>advanced,fetchImpl:async()=>new Response(JSON.stringify({...raw,expires_at:selectedAfter.expires_at}),{headers:{'content-type':'application/json'}})});
 assert.equal(result.expiresAt,advanced+900);assert.equal(result.maxExpiresAt,expected.maxExpiresAt);
});
test('completion clock cannot move backward, exceed request bound, or cross deadline',async()=>{
 for(const [clock,deadline]of[[()=>now-1,now+600],[()=>now+16,now+600],[()=>now+1,now+1],[()=>NaN,now+600]])await assert.rejects(checkCandidateToken('kody_at_SYNTHETIC_ONLY',{expected,deadline,now,clock,fetchImpl:async()=>new Response(JSON.stringify(raw),{headers:{'content-type':'application/json'}})}),e=>e.stage==='candidate-window'&&e.message==='Candidate token introspection refused');
});
test('syntax HTTP shape and binding diagnostics never expose underlying values',async()=>{
 const cases=[['bad','candidate-input',()=>{}],['kody_at_SYNTHETIC_ONLY','candidate-request',()=>{throw new Error('PRIVATE_DATA');}],['kody_at_SYNTHETIC_ONLY','candidate-http',()=>new Response('PRIVATE_DATA',{status:403})],['kody_at_SYNTHETIC_ONLY','candidate-shape',()=>new Response(JSON.stringify({data:raw}),{headers:{'content-type':'application/json'}})],['kody_at_SYNTHETIC_ONLY','candidate-binding',()=>new Response(JSON.stringify({...raw,id:'other'}),{headers:{'content-type':'application/json'}})]];
 for(const [token,stage,reply]of cases)await assert.rejects(checkCandidateToken(token,{expected,deadline:now+600,now,clock:()=>now,fetchImpl:async()=>reply()}),e=>e.stage===stage&&!JSON.stringify(e).includes('PRIVATE_DATA')&&e.message==='Candidate token introspection refused');
});
