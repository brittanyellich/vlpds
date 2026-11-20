import test from 'node:test';import assert from 'node:assert/strict';
import {once} from 'node:events';import {randomBytes} from 'node:crypto';
import {createProfileBridge,challengeMac,requestMac,responseMac,challengePath,assertionPath} from './bridge.mjs';
import {agentDid,principalDid,skillId} from '../pilot.mjs';

test('private profile bridge authenticates both directions, fixed body and boot epoch; never parses CAR',async t=>{
 const key=randomBytes(32);let calls=0;
 const dispatch=async()=>{calls++;return{kind:'profile_asserted',profileId:'prf_642a5cf465fa4528a8f7e075f29557c4',agentDid,principalDid};};
 const servers=[];t.after(async()=>{for(const s of servers){s.closeAllConnections();await new Promise(r=>s.close(r));}});
 async function start(){const s=createProfileBridge({key,dispatch});servers.push(s);s.listen(0,'127.0.0.1');await once(s,'listening');return`http://127.0.0.1:${s.address().port}`;}
 const origin=await start();const challenge=await(await fetch(origin+challengePath)).json();assert.equal(challenge.signature,challengeMac(key,challenge.boot));
 const body=JSON.stringify({eventId:'a'.repeat(64),agentDid,principalDid,skillId});
 const input={boot:challenge.boot,timestamp:String(Math.floor(Date.now()/1000)),nonce:randomBytes(32).toString('hex'),body};
 const headers={'content-type':'application/json','x-agent-bridge-boot':input.boot,'x-agent-bridge-timestamp':input.timestamp,'x-agent-bridge-nonce':input.nonce,'x-agent-bridge-signature':requestMac(key,input)};
 const first=await fetch(origin+assertionPath,{method:'POST',headers,body});const bytes=Buffer.from(await first.arrayBuffer());
 assert.equal(first.status,200);assert.equal(first.headers.get('x-agent-bridge-signature'),responseMac(key,{...input,response:bytes,status:200}));assert.equal(JSON.parse(bytes).eventId,'a'.repeat(64));assert.equal(calls,1);
 assert.equal((await fetch(origin+assertionPath,{method:'POST',headers,body})).status,401);assert.equal(calls,1);
 const other=await start();assert.equal((await fetch(other+assertionPath,{method:'POST',headers,body})).status,401,'previous boot request rejected after restart');
 const changed={...input,nonce:randomBytes(32).toString('hex')};const badHeaders={...headers,'x-agent-bridge-nonce':changed.nonce,'x-agent-bridge-signature':requestMac(key,changed)};
 assert.equal((await fetch(origin+assertionPath,{method:'POST',headers:badHeaders,body:body.replace(skillId,'arbitrary-execution')})).status,401);
 const wrongkey={...headers,'x-agent-bridge-signature':requestMac(randomBytes(32),input)};assert.equal((await fetch(origin+assertionPath,{method:'POST',headers:wrongkey,body})).status,401);assert.equal(calls,1);
});
