import test from 'node:test';import assert from 'node:assert/strict';
import {PilotProvider,checkBindings,ProviderPending,CardPending} from '../scripts/pilot-provider.mjs';import{PILOT}from'../scripts/pilot-activation-plan.mjs';
const opts={account:'a'.repeat(32),cfToken:'c'.repeat(40),deployToken:'d'.repeat(64)};
const json=v=>new Response(JSON.stringify(v),{headers:{'content-type':'application/json'}});
test('provider credential destination isolation and immutable image, no redirects',async()=>{
 const calls=[];let provider;provider=new PilotProvider({...opts,fetchImpl:async(url,r)=>{calls.push([url,r]);assert.equal(r.redirect,'error');
 if(url.includes('/_deploy/')){assert.equal(r.headers.Authorization,'Bearer '+opts.deployToken);return json({desired:provider.image,current:provider.image,running:true});}
 assert.ok(url.startsWith('https://api.cloudflare.com/'));assert.equal(r.headers.Authorization,'Bearer '+opts.cfToken);
 return json({success:true,result:{deployments:[{versions:[{version_id:PILOT.offWorker,percentage:100}]}],id:PILOT.offWorker,resources:{bindings:[],script:{etag:'e'.repeat(64)}}}});}});
 await provider.status();await provider.metadata();assert.equal(calls.length,3);
 await assert.rejects(provider.request('https://example.invalid/'));assert.equal(calls.length,3);
});
test('each phase sends at most one image-guarded POST, even on ambiguous timeout',async()=>{
 let count=0,p;p=new PilotProvider({...opts,fetchImpl:async(url,r)=>{if(r.method==='POST'){count++;assert.equal(r.headers['X-Deploy-Image'],p.image);throw new TypeError('RAW_SECRET');}
 return json({desired:p.image,current:p.image,running:true});}});
 await assert.rejects(p.restart('activate'),ProviderPending);await assert.rejects(p.restart('activate'));assert.equal(count,1);
});
test('binding state rejects unrelated drift, missing key, unexpected active caller and secrets',()=>{
 const ordinary={name:'PUBLIC_HOST',type:'plain_text',text:'pds.crate.social'},off={id:PILOT.offWorker,bindings:[ordinary,{name:'AGENT_A2A_ENABLED',type:'plain_text',text:'false'},{name:'AGENT_A2A_RUNTIME',type:'plain_text',text:'native-profile-v1'}]};
 const baseline=checkBindings(off,{enabled:false,provisioned:false});assert.equal(baseline.length,64);
 const provisioned=structuredClone(off);provisioned.bindings.push(...['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'].map(name=>({name,type:'secret_text'})));
 assert.equal(checkBindings(provisioned,{enabled:false,provisioned:true,baseline}),baseline);
 for(const change of [x=>x.bindings.pop(),x=>x.bindings[0].text='other',x=>x.bindings.push({name:'A2A_TOKEN',type:'secret_text'}),x=>x.bindings.push({name:'AGENT_A2A_CALLER_DID',type:'plain_text',text:'other'})]){const x=structuredClone(provisioned);change(x);assert.throws(()=>checkBindings(x,{enabled:false,provisioned:true,baseline}));}
});

test('current Card authority is fixed DID/key/controller/type and exact current PDS origin',async()=>{
 const did='did:plc:6tlvgafuonoighfrtpejff5m',doc={id:did,verificationMethod:[{id:did+'#card-signing',controller:did,type:'Multikey',publicKeyMultibase:PILOT.cardKey}],service:[{id:'#atproto_pds',type:'AtprotoPersonalDataServer',serviceEndpoint:'https://pds.crate.social'}]};
 const provider=d=>new PilotProvider({...opts,fetchImpl:async(url,r)=>{assert.equal(url,'https://plc.directory/'+did);assert.equal(r.headers.Authorization,undefined);return json(d);}});
 assert.equal(await provider(doc).currentCardKey(),PILOT.cardKey);
 for(const change of[x=>x.deactivated=true,x=>x.id='other',x=>x.verificationMethod[0].type='other',x=>x.verificationMethod[0].controller='other',x=>x.service[0].serviceEndpoint='https://other.invalid',x=>x.service.push(x.service[0])]){const d=structuredClone(doc);change(d);await assert.rejects(provider(d).currentCardKey());}
});

test('fixed DID accepts observed DID-LD media type; administrative JSON still rejects it',async()=>{
 const did='did:plc:6tlvgafuonoighfrtpejff5m',doc={id:did,verificationMethod:[{id:did+'#card-signing',controller:did,type:'Multikey',publicKeyMultibase:PILOT.cardKey}],service:[{id:'#atproto_pds',type:'AtprotoPersonalDataServer',serviceEndpoint:'https://pds.crate.social'}]};
 const p=new PilotProvider({...opts,fetchImpl:async()=>new Response(JSON.stringify(doc),{headers:{'content-type':'Application/DID+LD+JSON; charset=utf-8'}})});
 assert.equal(await p.currentCardKey(),PILOT.cardKey);await assert.rejects(p.status());
 const bad=new PilotProvider({...opts,fetchImpl:async()=>new Response(JSON.stringify({...doc,id:'other'}),{headers:{'content-type':'application/did+ld+json'}})});await assert.rejects(bad.currentCardKey());
 const html=new PilotProvider({...opts,fetchImpl:async()=>new Response(JSON.stringify(doc),{headers:{'content-type':'text/html'}})});await assert.rejects(html.currentCardKey());
});

// Reproduce the historical diagnostic ambiguity without a live request.
test('Card readiness groups native404 and upstream502/503/504 without proving account or trust',async()=>{
 for(const status of [404,502,503,504]){
  let cardRequests=0;
  const p=new PilotProvider({...opts,fetchImpl:async url=>{
   if(url.endsWith('/xrpc/_health'))return json({version:'synthetic'});
   if(url.endsWith('/account/spaces'))return new Response('/assets/index-D5JRYEyV.js',{headers:{'content-type':'text/html'}});
   assert.equal(url,'https://pds.crate.social/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/.well-known/agent-card.json');
   cardRequests++;return new Response('synthetic',{status});
  }});
  await assert.rejects(p.publicChecks(true),e=>e instanceof CardPending&&e.message==='Card pending'&&e.reason===`card-http-${status}-other`);
  assert.equal(cardRequests,1);
 }
});

test('Card labels retain only exact allowlisted native errors without body content',()=>{
 for(const [status,body,reason]of [
  [404,{error:'Agent unavailable'},'card-http-404-agent-unavailable'],
  [503,{error:'Signed Card trust unavailable'},'card-http-503-trust-unavailable'],
  [502,{error:'Signed Card trust unavailable'},'card-http-502-other'],
  [503,{error:'PRIVATE_RESPONSE'},'card-http-503-other'],
  [404,{error:'Agent unavailable',extra:'PRIVATE_RESPONSE'},'card-http-404-other'],
 ]){const e=new CardPending(status,Buffer.from(JSON.stringify(body)),'application/json');assert.equal(e.reason,reason);assert.ok(!JSON.stringify(e).includes('PRIVATE_RESPONSE'));}
 assert.equal(new CardPending(503,Buffer.from('PRIVATE_RESPONSE')).reason,'card-http-503-other');
 assert.throws(()=>new CardPending(401,Buffer.from('{}')));
});

test('Card observations do not relax OFF404, enabled200 or hard failure gates',async()=>{
 for(const [enabled,status,passes]of [[false,404,true],[true,200,true],[true,401,false],[false,200,false]]){
  let probes=0;const p=new PilotProvider({...opts,fetchImpl:async url=>{
   if(url.endsWith('/xrpc/_health'))return json({version:'synthetic'});
   if(url.endsWith('/account/spaces'))return new Response('/assets/index-D5JRYEyV.js',{headers:{'content-type':'text/html'}});
   assert.equal(url,'https://pds.crate.social/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/.well-known/agent-card.json');probes++;return new Response('{}',{status});
  }});
  if(passes)assert.equal((await p.publicChecks(enabled)).status,status);
  else await assert.rejects(p.publicChecks(enabled),e=>!(e instanceof ProviderPending));
  assert.equal(probes,1);
 }
});

test('native-looking labels require normalized JSON media type',()=>{
 for(const type of [undefined,'text/html','text/plain','application/did+ld+json']){
  assert.equal(new CardPending(503,Buffer.from('{"error":"Signed Card trust unavailable"}'),type).reason,'card-http-503-other');
 }
 assert.equal(new CardPending(503,Buffer.from('{"error":"Signed Card trust unavailable"}'),'application/json').reason,'card-http-503-trust-unavailable');
});
