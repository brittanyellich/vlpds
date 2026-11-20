import test from 'node:test';import assert from 'node:assert/strict';
import {cloudflareSecretTransport} from '../scripts/pilot-secret-transport.mjs';
const input=()=>({stdin:Buffer.from(JSON.stringify({AGENT_A2A_BRIDGE_KEY:'b'.repeat(64),AGENT_A2A_KODY_TOKEN:'kody_at_SYNTHETIC_ONLY'})),args:['secret','bulk','--name','crate-pds'],childEnv:{CLOUDFLARE_ACCOUNT_ID:'a'.repeat(32),CLOUDFLARE_API_TOKEN:'c'.repeat(40)}});
test('fixed secrets-bulk API request carries only two approved keys, no redirects',async()=>{
 let calls=0;const t=cloudflareSecretTransport(async(url,req)=>{calls++;assert.equal(url,`https://api.cloudflare.com/client/v4/accounts/${'a'.repeat(32)}/workers/scripts/crate-pds/secrets-bulk`);
 assert.equal(req.method,'PATCH');assert.equal(req.redirect,'error');assert.ok(req.signal);assert.equal(req.headers['Content-Type'],'application/merge-patch+json');
 const body=JSON.parse(req.body);assert.deepEqual(Object.keys(body.secrets).sort(),['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN']);assert.equal(body.secrets.AGENT_A2A_KODY_TOKEN.type,'secret_text');
 return new Response('{"success":true}',{headers:{'content-type':'application/json'}});});assert.equal(await t(input()),true);assert.equal(calls,1);
});
test('API errors, redirects, malformed or oversized receipts fail with sanitized error and no retry',async()=>{
 for(const response of [()=>new Response('RAW_SECRET',{status:403}),()=>new Response('',{status:302}),()=>new Response('{bad',{headers:{'content-type':'application/json'}}),()=>new Response(JSON.stringify({success:true,pad:'x'.repeat(20000)}),{headers:{'content-type':'application/json'}}),()=>new Response('{"success":false}',{headers:{'content-type':'application/json'}}),()=>{throw new Error('RAW_SECRET');}]){
 let count=0;await assert.rejects(cloudflareSecretTransport(async()=>{count++;return response();})(input()),/^Error: Pilot secret API failed; no retry$/);assert.equal(count,1);
 }
});
test('wrong destination/config/extra keys are rejected before API call',async()=>{
 for(const corrupt of [x=>x.args.push('other'),x=>x.childEnv.EXTRA='value',x=>x.childEnv.CLOUDFLARE_ACCOUNT_ID='other',x=>x.stdin=Buffer.from('{"other":"secret"}')]){
 let count=0;const x=input();corrupt(x);await assert.rejects(cloudflareSecretTransport(async()=>{count++;})(x));assert.equal(count,0);
 }
});
