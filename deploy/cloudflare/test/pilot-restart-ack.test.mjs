import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {stripTypeScriptTypes} from 'node:module';
import {PilotProvider,ProviderPending} from '../scripts/pilot-provider.mjs';

const opts={account:'a'.repeat(32),cfToken:'c'.repeat(40),deployToken:'d'.repeat(64)};
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json'}});
// Execute the actual handler; only the platform base, container and storage are
// synthetic. This proves the ACK contract, not Cloudflare reset scheduling.
let source=await readFile(new URL('../src/index.ts',import.meta.url),'utf8');
source=source.replace('import { DurableObject } from "cloudflare:workers";',
 'class DurableObject { constructor(ctx,env){this.ctx=ctx;this.env=env;} }')
 .replaceAll(/from "\.\/(.*?)"/g,(_,path)=>`from "${new URL('../src/'+path,import.meta.url).href}"`);
const {Pds}=await import('data:text/javascript;base64,'+Buffer.from(stripTypeScriptTypes(source,{mode:'strip'})).toString('base64'));

for(const cold of [false,true])test(`actual handler ACK accepted after ${cold?'cold start race':'warm restart'}, without replay`,async()=>{
 let p,posts=0,starts=0,signals=0,ack,resolveExit;
 const env=new Proxy({ADMIN_HOST:'admin.crate.social',ENABLED:'true',AGENT_A2A_ENABLED:'false',DEPLOY_TOKEN:opts.deployToken,CF_ACCOUNT_ID:opts.account},{get:(v,k)=>v[k]??'synthetic'});
 const container={running:true,images:{},inspect:async()=>({image:p.image}),setInactivityTimeout:async()=>{},
  monitor:()=>new Promise(resolve=>{resolveExit=resolve;}),signal(){signals++;this.running=false;resolveExit();},
  start(config){starts++;this.running=true;assert.equal(config.image,p.image);assert.equal(config.env.VLPDS_AGENT_A2A_ENABLED,undefined);assert.equal(config.entrypoint[2],'vlpds');}};
 const ctx={container,storage:{setAlarm:async()=>{}},blockConcurrencyWhile:fn=>fn()};
 p=new PilotProvider({...opts,fetchImpl:async(url,r)=>{
  container.images.pds=p.image;
  if(r.method==='POST'){posts++;if(cold)container.running=false;}
  const response=await new Pds(ctx,env).fetch(new Request(url,r));
  if(r.method==='POST'){assert.equal(response.status,202);ack=await response.clone().json();}
  return response;
 }});
 await p.restart('disable');assert.equal(ack.restarted,!cold);assert.equal(starts,1);assert.equal(signals,cold?0:1);
 await assert.rejects(p.restart('disable'));assert.equal(posts,1);
});

test('invalid restart ACKs fail closed and cannot be replayed',async()=>{
 for(const change of [a=>delete a.restarted,a=>a.restarted=null,a=>a.restarted=0,a=>a.restarted='false',a=>a.starting=false,a=>a.desired='other']){
  let p,posts=0;p=new PilotProvider({...opts,fetchImpl:async(_,r)=>{
   if(r.method!=='POST')return json({desired:p.image,current:p.image,running:true});
   posts++;const ack={desired:p.image,starting:true,restarted:false};change(ack);return json(ack,202);
  }});
  await assert.rejects(p.restart('disable'));await assert.rejects(p.restart('disable'));assert.equal(posts,1);
 }
 for(const response of [()=>json({starting:true,restarted:false},503),()=>new Response('not-json',{status:202}),()=>{throw new TypeError('synthetic transport failure');}]){
  let p,posts=0;p=new PilotProvider({...opts,fetchImpl:async(_,r)=>{if(r.method!=='POST')return json({desired:p.image,current:p.image,running:true});posts++;return response();}});
  await assert.rejects(p.restart('disable'));await assert.rejects(p.restart('disable'));assert.equal(posts,1);
 }
});

test('cold or unqualified precheck still sends no POST',async()=>{
 for(const status of [{running:false,current:null},{running:false,current:'qualified'},{running:true,current:'other'}]){
  let p,posts=0;p=new PilotProvider({...opts,fetchImpl:async(_,r)=>{if(r.method==='POST')posts++;return json({desired:p.image,...status,current:status.current==='qualified'?p.image:status.current});}});
  await assert.rejects(p.restart('disable'),status.running?Error:ProviderPending);assert.equal(posts,0);
 }
});
