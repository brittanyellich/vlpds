import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,statSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {parsePublishAcknowledgement,publishPilotWorker} from '../scripts/pilot-publish.mjs';
const id='01234567-89ab-cdef-0123-456789abcdef';
const entry={type:'deploy',version:1,worker_name:'crate-pds',version_id:id,timestamp:'2026-11-21T00:00:00.000Z'};
const session={type:'wrangler-session',version:1,wrangler_version:'4.158.0'};
const bytes=(x,s=session)=>Buffer.from(JSON.stringify(s)+'\n'+JSON.stringify(x)+'\n');
test('structured acknowledgement succeeds without human log marker',()=>{
 const tmp=mkdtempSync(join(tmpdir(),'exp710-publish-'));let calls=0;
 try{assert.equal(publishPilotWorker({root:'/fixture',tmp,configPath:'/fixture/config',account:'synthetic',token:'SYNTHETIC',execute:(_b,args,o)=>{
  calls++;assert.deepEqual(args.slice(1),['deploy','--name','crate-pds','--config','/fixture/config','--containers-rollout','none']);assert.equal(o.env.WRANGLER_LOG,'info');assert.equal(statSync(o.env.WRANGLER_OUTPUT_FILE_PATH).mode&0o777,0o600);
  writeFileSync(o.env.WRANGLER_OUTPUT_FILE_PATH,bytes(entry));return Buffer.alloc(0);
 }}),id);assert.equal(calls,1);}finally{rmSync(tmp,{recursive:true,force:true});}
});
test('missing malformed duplicate wrong-worker version ID and oversized receipts deny',()=>{
 for(const v of [Buffer.alloc(0),Buffer.from('{'),Buffer.from([0xff]),Buffer.concat([bytes(entry),bytes(entry)]),bytes({...entry,type:'error'}),bytes({...entry,worker_name:'other'}),bytes({...entry,version:2}),bytes({...entry,version_id:'x'}),bytes({...entry,version_id:id+'\n'}),bytes(entry,{...session,wrangler_version:'other'}),bytes(entry,{...session,type:'error'}),Buffer.from(JSON.stringify(entry)+'\n'),bytes({...entry,version_id:undefined}),Buffer.alloc(65537)])assert.throws(()=>parsePublishAcknowledgement(v),/reconcile read-only/);
});
test('failure or timeout after receipt never accepts retries or leaks output',()=>{
 for(const code of ['EXIT_FAILURE','ETIMEDOUT']){
  const tmp=mkdtempSync(join(tmpdir(),'exp710-publish-'));let calls=0;
  try{assert.throws(()=>publishPilotWorker({root:'/fixture',tmp,configPath:'/fixture/config',execute:(_b,_a,o)=>{calls++;writeFileSync(o.env.WRANGLER_OUTPUT_FILE_PATH,bytes(entry));throw Object.assign(new Error('PRIVATE_OUTPUT'),{code,stdout:'PRIVATE_OUTPUT'});}}),e=>!String(e).includes('PRIVATE_OUTPUT')&&/reconcile read-only/.test(e.message));assert.equal(calls,1);}finally{rmSync(tmp,{recursive:true,force:true});}
 }
});
test('zero exit and human marker alone do not acknowledge publish',()=>{
 const tmp=mkdtempSync(join(tmpdir(),'exp710-publish-'));try{assert.throws(()=>publishPilotWorker({root:'/fixture',tmp,configPath:'/fixture/config',execute:()=>Buffer.from('Current Version ID: '+id)}),/reconcile read-only/);}finally{rmSync(tmp,{recursive:true,force:true});}
});
