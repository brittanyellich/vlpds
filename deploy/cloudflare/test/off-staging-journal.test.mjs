import test from 'node:test';
import assert from 'node:assert/strict';
import {createOffJournal} from '../scripts/off-staging-journal.mjs';
const head='a'.repeat(40),run='46036316105';
const options=token=>({token,head,run,operation:'stage'});
const response=value=>new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});
test('opaque classic and JWT-shaped tokens reach only the fixed journal endpoint unchanged',async()=>{
 for(const token of ['ghs_'+'a'.repeat(36),'opaque_+/'+'a'.repeat(30)+'=~','ghs_123456_'+'a'.repeat(180)+'.'+'b-_'.repeat(120)+'.'+'c'.repeat(100)]){
  let calls=0;
  const journal=createOffJournal({...options(token),fetchImpl:async(url,request)=>{
   calls++;assert.ok(url.startsWith('https://api.github.com/repos/brittanyellich/vlpds/deployments'));assert.equal(request.redirect,'error');assert.equal(request.headers.Authorization,'Bearer '+token);
   if(request.method==='GET')return response([]);
   assert.equal(request.method,'POST');return new Response(JSON.stringify({id:123,sha:head,task:'exp710-off-stage-ea8627d4'}),{status:201});
  }});
  assert.equal(calls,0);assert.equal(await journal.claim('synthetic'),true);assert.equal(calls,2);await assert.rejects(journal.claim('synthetic'));assert.equal(calls,2);
 }
});
test('invalid bearer header values fail synchronously without IO or value disclosure',()=>{
 for(const token of [undefined,null,42,{},'', 'a'.repeat(19),'a'.repeat(8193),'a'.repeat(20)+'\r\nX-Injected: yes','a'.repeat(20)+' ','a'.repeat(20)+'\n','a'.repeat(20)+'\r','a'.repeat(20)+'\t','a'.repeat(20)+'\x7f','a'.repeat(20)+'\0','a'.repeat(20)+'é']){
  let calls=0;assert.throws(()=>createOffJournal({...options(token),fetchImpl:async()=>{calls++;throw new Error('unexpected');}}),error=>error.message==='OFF execution journal refused; no replay');assert.equal(calls,0);
 }
});
test('long-token compatibility preserves constructor identity and operation guards',()=>{
 const token='ghs_123_'+'a'.repeat(300)+'.b.c';
 for(const invalid of [{head:'bad'},{run:'bad'},{operation:'enable'}])assert.throws(()=>createOffJournal({...options(token),...invalid}));
});
