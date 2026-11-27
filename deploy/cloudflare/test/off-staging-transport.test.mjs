import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync,readFileSync,mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {OFF_STAGE as P,offImage,qualifyOffTransition} from '../scripts/off-staging-plan.mjs';
import {createOffTransport,moduleHash,runOffStage,validateStageConfig,createOffDiagnostics,OFF_STAGE_CATEGORIES,prepareOffBundle} from '../scripts/off-staging-transport.mjs';
import {createOffJournal} from '../scripts/off-staging-journal.mjs';
const pairs=[["ADMIN_HOST","plain_text"],["ADMIN_TOKEN","secret_text"],["AGENT_A2A_ENABLED","plain_text"],["AGENT_A2A_RUNTIME","plain_text"],["CF_ACCOUNT_ID","secret_text"],["DEPLOY_TOKEN","secret_text"],["EMAIL_API_TOKEN","secret_text"],["EMAIL_API_URL","secret_text"],["EMAIL_FROM_ADDRESS","secret_text"],["ENABLED","plain_text"],["HANDLE_DOMAIN","plain_text"],["INTERNAL_TOKEN","secret_text"],["JWT_SECRET","secret_text"],["KEK","secret_text"],["OPERATOR_DID","plain_text"],["PDS","durable_object_namespace"],["PLC_RECOVERY_DID_KEY","secret_text"],["PLC_ROTATION_KEY_HEX","secret_text"],["PUBLIC_HOST","plain_text"],["S3_ACCESS_KEY","secret_text"],["S3_BUCKET","plain_text"],["S3_PREFIX","plain_text"],["S3_SECRET_KEY","secret_text"]];
const account='a'.repeat(32),worker='11111111-1111-1111-1111-111111111111',head='c'.repeat(40),hash=b=>createHash('sha256').update(b).digest('hex');
const json=(v,status=200)=>new Response(JSON.stringify(v),{status,headers:{'content-type':'application/json'}});
const bindings=()=>pairs.map(([name,type])=>({name,type,...(type==='plain_text'?{text:name==='AGENT_A2A_ENABLED'?'false':name==='AGENT_A2A_RUNTIME'?'native-profile-v1':'synthetic'}:{})}));
const moduleResponse=(bytes,entry='index.js')=>{const f=new FormData();f.append('index.js',new File([bytes],'index.js',{type:'application/javascript'}));const r=new Response(f);r.headers.set('cf-entrypoint',entry);return r;};
function fixture(t){
 const tmp=mkdtempSync(join(tmpdir(),'off-transport-test-'));t.after(()=>rmSync(tmp,{recursive:true,force:true}));
 const bundle=Buffer.from('export default {fetch(){return new Response("synthetic")}}'),bundlePath=join(tmp,'index.js'),configPath=join(tmp,'config.json');writeFileSync(bundlePath,bundle);const configBytes=JSON.stringify({vars:Object.fromEntries(bindings().filter(b=>b.type==='plain_text').map(b=>[b.name,b.text]))});writeFileSync(configPath,configBytes);
 const events=[],claimed=new Set();let time=100,active=P.worker,script=P.script,desired=P.rollback,current=P.rollback,content=bundle,drift=false,latest=P.worker,delay=0,pendingActivation;
 const api=`https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/crate-pds`;
 const fetchImpl=async(url,r)=>{
  events.push([r.method,url]);assert.equal(r.redirect,'error');assert.ok(r.signal);assert.equal(r.headers.Authorization,`Bearer ${url.startsWith('https://api.cloudflare.com/')?'c'.repeat(40):'d'.repeat(64)}`);
  if(url===api+'/deployments'&&r.method==='GET'){if(pendingActivation&&delay--<=0){active=pendingActivation;script=active===P.worker?P.script:'b'.repeat(64);desired=active===P.worker?P.rollback:P.candidate;pendingActivation=undefined;}return json({success:true,result:{deployments:[{versions:[{version_id:active,percentage:100}]}]}});}
  if(url===api+'/versions?per_page=1')return json({success:true,result:{items:[{id:latest}]}});
  if(url===api+'/versions/'+active||url===api+'/versions/'+latest){const inactive=url===api+'/versions/'+latest&&latest!==active;const b=bindings();if(drift)b.find(b=>b.name==='S3_BUCKET').text='changed';return json({success:true,result:{id:inactive?latest:active,resources:{script:{etag:inactive?'b'.repeat(64):script},bindings:b,script_runtime:{containers:[{name:'crate-pds-pds',class_name:'Pds',images:{pds:offImage(account,inactive?P.candidate:desired)}}]}}}});}
  if(url.endsWith('/containers/image-preparations')){assert.ok([offImage(account,P.candidate),offImage(account,P.rollback)].includes(JSON.parse(r.body).image));return json({success:true,result:{status:'ready'}});}
  if(url===api+'/versions?bindings_inherit=strict'&&r.method==='POST'){const m=JSON.parse(r.body.get('metadata'));assert.equal(m.containers[0].images.pds,offImage(account,P.candidate));assert.ok(m.bindings.filter(b=>b.type!=='plain_text').every(b=>b.type==='inherit'));assert.equal(hash(Buffer.from(await r.body.get('index.js').arrayBuffer())),hash(bundle));events.push(['publish']);latest=worker;return json({success:true,result:{id:worker}});}
  if(url===api+'/content/v2')return moduleResponse(content);
  if(url===api+'/deployments'&&r.method==='POST'){const body=JSON.parse(r.body);assert.equal(body.code_update_strategy,'immediate');const id=body.versions[0].version_id;if(delay>0){pendingActivation=id;}else if(id===P.worker){active=P.worker;script=P.script;desired=P.rollback;}else{assert.equal(id,worker);active=worker;script='b'.repeat(64);desired=P.candidate;}return json({success:true,result:{strategy:'percentage',versions:[{percentage:100,version_id:id}]}});}
  if(url==='https://admin.crate.social/_deploy/status')return json({desired:offImage(account,desired),current:offImage(account,current),running:true});
  if(url==='https://admin.crate.social/_deploy/restart'){assert.equal(r.headers['X-Deploy-Image'],offImage(account,desired));current=desired;return json({desired:offImage(account,desired),starting:true,restarted:true},202);}
  // Public requests have no authorization; these are handled in outer wrapper.
  throw new Error('Unexpected fixed authenticated endpoint');
 };
 const fetcher=async(url,r)=>{
  if(url.startsWith('https://pds.crate.social/')){assert.equal(r.method,'GET');assert.equal(r.headers.Authorization,undefined);events.push(['GET',url]);
   if(url.endsWith('/xrpc/_health'))return json({version:'1.3.0+'+(current===P.candidate?P.revision:P.rollbackRevision)});
   if(url.endsWith('/account/spaces'))return new Response('<script src="/assets/index-D5JRYEyV.js"></script>',{headers:{'content-type':'text/html'}});
   if(url.includes('/.well-known/agent-card.json'))return new Response('not found',{status:404});
   throw new Error('Unexpected public URL');
  }return fetchImpl(url,r);
 };
 const journal={claim:async id=>{if(claimed.has(id))return false;claimed.add(id);return true;},phase:async phase=>events.push(['journal',phase])};
 const prepare=()=>({revision:P.revision,manifest:P.candidate,ociConfig:P.config,script:hash(bundle),bundlePath,configPath,configHash:hash(configBytes)});
 const make=overrides=>createOffTransport({account,cfToken:'c'.repeat(40),deployToken:'d'.repeat(64),root:tmp,tmp,journal,env:{},fetchImpl:fetcher,now:()=>time,sleep:async ms=>{time+=ms/1000;},prepare,...overrides});
 const run=(transport,operation='stage',staged,onStage)=>qualifyOffTransition({operation,account,transport,now:()=>time,staged,onStage,grant:{operation,id:operation==='stage'?'22222222-2222-2222-2222-222222222222':'33333333-3333-3333-3333-333333333333',candidate:P.candidate,rollbackWorker:P.worker,exclusiveWindow:true,expiresAt:600}});
 return {make,run,events,fetcher,journal,prepare,tmp,configPath,bundlePath,setDelay:n=>delay=n,setTime:v=>time=v,setContent:b=>content=b,setDrift:v=>drift=v};
}
test('real transport performs exact candidate stage and exact existing-version recovery against synthetic provider only',async t=>{
 const f=fixture(t),staged=await f.run(f.make());assert.equal(staged.worker,worker);assert.equal(staged.nativeOffSelfAttestation,false);
 const restored=await f.run(f.make(),'rollback',staged);assert.equal(restored.worker,P.worker);
 assert.equal(f.events.filter(e=>e[0]==='publish').length,1);assert.equal(f.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/restart')).length,2);assert.equal(f.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/deployments')).length,2);
});
test('downloaded source tampering stops before restart; no upload replay',async t=>{
 const f=fixture(t);f.setContent(Buffer.from('unreviewed'));await assert.rejects(f.run(f.make()));assert.equal(f.events.filter(e=>e[0]==='publish').length,1);assert.equal(f.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/restart')).length,0);
});
test('local prepared bundle mutation prevents upload, including zero-byte and symlink-like missing inputs',async t=>{
 const f=fixture(t),transport=f.make();await transport.snapshot();await transport.prepare({revision:P.revision,manifest:P.candidate,ociConfig:P.config});writeFileSync(f.bundlePath,'tampered');await assert.rejects(transport.publish({script:f.prepare().script}));assert.ok(!f.events.some(e=>e[0]==='publish'));
});
test('ordinary binding drift before mutation denies all provider writes',async t=>{
 const f=fixture(t);let reads=0;const fetchImpl=async(url,r)=>{if(url.endsWith('/deployments')&&++reads>2)f.setDrift(true);return f.fetcher(url,r);};await assert.rejects(f.run(f.make({fetchImpl})));assert.ok(!f.events.some(e=>e[0]==='publish'||e[0]==='POST'));
});
test('invalid restart ACK and ambiguous restore are not replayed',async t=>{
 const f=fixture(t),fetchImpl=async(url,r)=>{const result=await f.fetcher(url,r);return r.method==='POST'&&url.endsWith('/restart')?json({starting:true},202):result;};await assert.rejects(f.run(f.make({fetchImpl})));assert.equal(f.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/restart')).length,1);
 const g=fixture(t),staged=await g.run(g.make());let restores=0;const failed=async(url,r)=>{if(r.method==='POST'&&url.endsWith('/deployments')){restores++;throw new Error('private provider error');}return g.fetcher(url,r);};await assert.rejects(g.run(g.make({fetchImpl:failed}),'rollback',staged));assert.equal(restores,1);
});
test('module inspection rejects wrong entrypoint, duplicates and non-module responses',async()=>{
 for(const r of [new Response('not modules'),moduleResponse('x','wrong.js')])await assert.rejects(moduleHash(r));
 const f=new FormData();f.append('index.js',new File(['a'],'index.js'));f.append('index.js',new File(['b'],'index.js'));const r=new Response(f);r.headers.set('cf-entrypoint','index.js');await assert.rejects(moduleHash(r));
});
test('production entry rejects foreign account/context before any IO and retains only sanitized receipt',async t=>{
 const f=fixture(t);let calls=0;const result=await runOffStage({RUNNER_TEMP:f.tmp,OPERATION:'stage',GITHUB_RUN_ID:'45843254751',GITHUB_SHA:head},{fetchImpl:async()=>{calls++;throw new Error('SECRET');}});assert.equal(result.result,'failed');assert.equal(calls,0);assert.ok(!readFileSync(join(f.tmp,'exp710-off-staging-receipt.json'),'utf8').includes('SECRET'));assert.deepEqual(result.diagnostics,{version:1,failedStage:'execution-context'});
});
test('durable GitHub journal blocks duplicates across fresh objects and ambiguous intent never repeats',async()=>{
 let records=[],creates=0;const fetchImpl=async(url,r)=>{assert.ok(url.startsWith('https://api.github.com/repos/brittanyellich/vlpds/deployments'));assert.equal(r.redirect,'error');if(r.method==='GET')return json(records);creates++;const b=JSON.parse(r.body);assert.equal(b.auto_merge,false);records=[{...b,id:42,sha:head}];return json(records[0],201);};
 const options={token:'t'.repeat(40),head,run:'45843254751',operation:'stage',fetchImpl};assert.equal(await createOffJournal(options).claim('id'),true);await assert.rejects(createOffJournal(options).claim('id'));assert.equal(creates,1);
 let posts=0;const j=createOffJournal({...options,fetchImpl:async(_,r)=>{if(r.method==='GET')return json([]);posts++;throw new Error('ambiguous');}});await assert.rejects(j.claim('id'));await assert.rejects(j.claim('id'));assert.equal(posts,1);
});
test('manual workflow has one provider entry, no registry/build trigger, fixed candidate and explicit freeze',()=>{
 const w=readFileSync(new URL('../../../.github/workflows/cloudflare-off-staging.yml',import.meta.url),'utf8');assert.match(w,/workflow_dispatch:/);assert.ok(!/^  (push|pull_request|schedule):/m.test(w));assert.match(w,/default: false/);assert.match(w,/deployments: write/);assert.match(w,/703c118c66277ca42c45808a2f6cc620429c6718/);assert.ok(!/skopeo|docker |registries credentials|secret bulk/.test(w));assert.equal((w.match(/node deploy\/cloudflare\/scripts\/off-staging-transport.mjs/g)||[]).length,1);
});

test('30-second snapshot deadline aborts late continuations before another IO',async t=>{
 const f=fixture(t);let resolve,requests=0;
 const transport=f.make({fetchImpl:async()=>{requests++;return new Promise(r=>resolve=r);}});
 t.mock.timers.enable({apis:['setTimeout']});
 const pending=transport.snapshot();t.mock.timers.tick(30001);await assert.rejects(pending);
 resolve(json({success:true,result:{deployments:[{versions:[{version_id:P.worker,percentage:100}]}]}}));
 await new Promise(r=>queueMicrotask(r));await new Promise(r=>queueMicrotask(r));assert.equal(requests,1);
});
test('protected configuration variables must match independent live metadata before claim or upload',async t=>{
 const f=fixture(t);writeFileSync(f.configPath,JSON.stringify({vars:{S3_BUCKET:'wrong'}}));await assert.rejects(f.run(f.make()));assert.ok(!f.events.some(e=>e[0]==='publish'||e[0]==='journal'));
});
test('production configuration rejects additional builds, routes, assets and migrations',()=>{
 const c={name:'crate-pds',account_id:account,containers:[{class_name:'Pds',scheduling_policy:'durable_object',images:{pds:{image:offImage(account,P.candidate)}}}],main:'src/index.ts',compatibility_date:'2026-11-05',compatibility_flags:['nodejs_compat'],workers_dev:false,preview_urls:false,routes:['pds.crate.social/*','admin.crate.social/*','*.crate.social/.well-known/atproto-did'].map(pattern=>({pattern,zone_name:'crate.social'})),durable_objects:{bindings:[{name:'PDS',class_name:'Pds'}]},migrations:[{tag:'v1',new_sqlite_classes:['Pds']}]};
 validateStageConfig(c);
 for(const patch of [{containers:[{...c.containers[0],max_instances:9}]},{assets:{}},{build:{command:'unreviewed'}},{routes:[{pattern:'other/*',zone_name:'crate.social'}]},{migrations:[{tag:'v2',new_sqlite_classes:['Other']}]},{compatibility_flags:['nodejs_compat','extra']}])assert.throws(()=>validateStageConfig({...c,...patch}));
});

test('pinned Wrangler dry-run preserves the exact prebundled module without credentials or registry access',t=>{
 const f=fixture(t),root=new URL('..',import.meta.url).pathname;
 const source=join(f.tmp,'source.json'),out=join(f.tmp,'out'),again=join(f.tmp,'again');
 const config={name:'crate-pds',main:join(f.tmp,'index.ts'),compatibility_date:'2026-11-05',compatibility_flags:['nodejs_compat'],containers:[{class_name:'Pds',scheduling_policy:'durable_object',images:{pds:{image:offImage(account,P.candidate)}}}],durable_objects:{bindings:[{name:'PDS',class_name:'Pds'}]},migrations:[{tag:'v1',new_sqlite_classes:['Pds']}]};
 writeFileSync(join(f.tmp,'index.ts'),'import { DurableObject } from "cloudflare:workers"; export class Pds extends DurableObject {} export default { fetch(){return new Response("synthetic")} };');
 writeFileSync(source,JSON.stringify(config));
 const safe={PATH:'/usr/bin:/bin',HOME:f.tmp,TMPDIR:f.tmp,CI:'true',WRANGLER_SEND_METRICS:'false',WRANGLER_LOG:'error'};
 const dry=(path,dest)=>execFileSync(process.execPath,[join(root,'node_modules/wrangler/bin/wrangler.js'),'deploy','--dry-run','--config',path,'--outdir',dest,'--containers-rollout','none'],{cwd:root,env:safe,stdio:'pipe',timeout:30000,maxBuffer:262144});
 dry(source,out);const bytes=readFileSync(join(out,'index.js'));
 const frozen=join(f.tmp,'frozen.json');writeFileSync(frozen,JSON.stringify({...config,main:join(out,'index.js'),no_bundle:true,find_additional_modules:false,upload_source_maps:false}));
 dry(frozen,again);assert.deepEqual(readFileSync(join(again,'index.js')),bytes);
});

test('ambiguous activation may retain a byte-verified recovery checkpoint but always stops before restart',async t=>{
 const f=fixture(t),checkpoints=[];let activations=0;
 const fetchImpl=async(url,r)=>{const response=await f.fetcher(url,r);if(r.method==='POST'&&url.endsWith('/deployments')){activations++;throw new Error('ambiguous activation');}return response;};
 const transport=f.make({onCheckpoint:c=>checkpoints.push(c),fetchImpl});
 await assert.rejects(f.run(transport));assert.equal(activations,1);assert.equal(checkpoints.length,1);assert.equal(checkpoints[0].worker,worker);assert.equal(f.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/restart')).length,0);
 await assert.rejects(transport.publish({script:f.prepare().script}));assert.equal(activations,1);
});

test('strict inheritance refuses a newer inactive version before any provider write',async t=>{
 const f=fixture(t),fetchImpl=async(url,r)=>url.endsWith('/versions?per_page=1')?json({success:true,result:{items:[{id:worker}]}}):f.fetcher(url,r);
 await assert.rejects(f.run(f.make({fetchImpl})));assert.ok(!f.events.some(e=>e[0]==='POST'));
});
test('image preparation polls only explicit pending status and never retries an HTTP failure',async t=>{
 const f=fixture(t);let preparations=0;
 const fetchImpl=async(url,r)=>{const response=await f.fetcher(url,r);if(url.endsWith('/image-preparations')&&++preparations===1)return json({success:true,result:{status:'pending'}});return response;};
 await f.run(f.make({fetchImpl}));assert.equal(preparations,3);assert.equal(f.events.filter(e=>e[0]==='publish').length,1);
 const g=fixture(t);let failures=0;const failed=async(url,r)=>{if(url.endsWith('/image-preparations')){failures++;return json({success:false},500);}return g.fetcher(url,r);};
 await assert.rejects(g.run(g.make({fetchImpl:failed})));assert.equal(failures,1);assert.ok(!g.events.some(e=>e[0]==='publish'));
});
test('expired authority after durable journal IO sends no provider mutation',async t=>{
 const f=fixture(t),journal={claim:f.journal.claim,phase:async()=>f.setTime(601)};
 await assert.rejects(f.run(f.make({journal,expiresAt:600})));assert.ok(!f.events.some(e=>e[0]==='POST'));
});

test('known old deployments may propagate for a bounded period without replaying stage or recovery',async t=>{
 const f=fixture(t);f.setDelay(4);const staged=await f.run(f.make());f.setDelay(4);await f.run(f.make(),'rollback',staged);
 assert.equal(f.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/deployments')).length,2);assert.equal(f.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/restart')).length,2);
 const g=fixture(t);g.setDelay(1000);await assert.rejects(g.run(g.make()));assert.equal(g.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/deployments')).length,1);assert.ok(!g.events.some(e=>e[0]==='POST'&&e[1].endsWith('/restart')));
});

test('closed diagnostic categories never retain arbitrary error/value text and preserve first failure',()=>{
 const d=createOffDiagnostics();assert.throws(()=>d.mark('SECRET/raw/url/or/token'));d.mark('runtime-status');d.capture();d.mark('public-health');d.capture();assert.deepEqual(d.snapshot(),{version:1,failedStage:'runtime-status'});assert.ok(!JSON.stringify(d.snapshot()).includes('SECRET'));assert.ok(OFF_STAGE_CATEGORIES.includes(d.snapshot().failedStage));
});
test('synthetic preflight refusals retain distinct bounded categories with zero provider writes',async t=>{
 const cases=[
  ['provider-metadata',url=>url.endsWith('/deployments'),()=>json({error:'SECRET'},403)],
  ['runtime-status',url=>url.endsWith('/_deploy/status'),()=>json({desired:'SECRET',current:'SECRET',running:true})],
  ['container-map',url=>url.includes('/versions/'),async response=>{const v=await response.json();v.result.resources.script_runtime.containers=[];return json(v);} ],
  ['public-health',url=>url.endsWith('/_health'),()=>json({error:'SECRET'},401)],
  ['public-ui',url=>url.endsWith('/account/spaces'),()=>new Response('SECRET',{status:418})],
  ['public-card',url=>url.includes('/.well-known/agent-card.json'),()=>new Response('SECRET',{status:200})],
  ['off-bindings',url=>url.includes('/versions/'),async response=>{const v=await response.json();v.result.resources.bindings.find(b=>b.name==='AGENT_A2A_ENABLED').text='true';return json(v);} ],
  ['snapshot-validation',url=>url.endsWith('/_health'),()=>json({version:'SECRET'})],
  ['latest-uploaded-version',url=>url.endsWith('/versions?per_page=1'),()=>json({success:true,result:{items:[{id:worker}]}})],
 ];
 for(const [stage,matches,change] of cases){const f=fixture(t),d=createOffDiagnostics();const fetchImpl=async(url,r)=>{const response=await f.fetcher(url,r);return matches(url)?change(response):response;};await assert.rejects(f.run(f.make({fetchImpl,onStage:d.mark,onFailure:d.capture}),'stage',undefined,d.mark));d.capture();assert.equal(d.snapshot().failedStage,stage);assert.ok(!JSON.stringify(d.snapshot()).includes('SECRET'));assert.ok(!f.events.some(e=>e[0]==='POST'||e[0]==='journal'));}
});
test('config mismatch and injected source preparation remain distinguishable without exposing values',async t=>{
 for(const stage of ['config-live-match','source-prepare']){const f=fixture(t),d=createOffDiagnostics();if(stage==='config-live-match')writeFileSync(f.configPath,JSON.stringify({vars:{SECRET:'SECRET'}}));const options={onStage:d.mark,onFailure:d.capture,...(stage==='source-prepare'?{prepare:()=>{throw new Error('SECRET');}}:{})};await assert.rejects(f.run(f.make(options),'stage',undefined,d.mark));d.capture();assert.equal(d.snapshot().failedStage,stage);assert.ok(!JSON.stringify(d.snapshot()).includes('SECRET'));assert.ok(!f.events.some(e=>e[0]==='POST'));}
});
test('source identity, toolchain and protected-config diagnostics run without credentials or subprocesses',t=>{
 const f=fixture(t);mkdirSync(join(f.tmp,'node_modules/wrangler'),{recursive:true});writeFileSync(join(f.tmp,'node_modules/wrangler/package.json'),JSON.stringify({version:'4.158.0'}));
 const execute=(_,args)=>Buffer.from(args[0]==='rev-parse'?(args[1]==='HEAD'?P.revision:'a5578cb57829d36f4f2c0bb7f1b507af8783a023'):'');
 const d=createOffDiagnostics();assert.throws(()=>prepareOffBundle({env:{CLOUDFLARE_ACCOUNT_ID:account},root:f.tmp,tmp:f.tmp,execute,onStage:d.mark}));d.capture();assert.equal(d.snapshot().failedStage,'protected-account');
 const wrong=createOffDiagnostics();assert.throws(()=>prepareOffBundle({env:{},root:f.tmp,tmp:f.tmp,execute:()=>Buffer.from('wrong'),onStage:wrong.mark}));wrong.capture();assert.equal(wrong.snapshot().failedStage,'source-identity');
 writeFileSync(join(f.tmp,'node_modules/wrangler/package.json'),JSON.stringify({version:'wrong'}));const tool=createOffDiagnostics();assert.throws(()=>prepareOffBundle({env:{},root:f.tmp,tmp:f.tmp,execute,onStage:tool.mark}));tool.capture();assert.equal(tool.snapshot().failedStage,'toolchain');
});

test('diagnostics add no IO and keep successful transition output unchanged',async t=>{
 const plain=fixture(t),observed=fixture(t),d=createOffDiagnostics();const a=await plain.run(plain.make());const b=await observed.run(observed.make({onStage:d.mark,onFailure:d.capture}),'stage',undefined,d.mark);assert.deepEqual(a,b);assert.deepEqual(plain.events,observed.events);assert.deepEqual(d.snapshot(),{version:1,failedStage:null});
});
test('first execution failure survives read-only reconciliation without error text',async t=>{
 const f=fixture(t),d=createOffDiagnostics();const fetchImpl=async(url,r)=>{const response=await f.fetcher(url,r);if(r.method==='POST'&&url.endsWith('/deployments'))throw new Error('SECRET/auth/header/body');return response;};await assert.rejects(f.run(f.make({fetchImpl,onStage:d.mark,onFailure:d.capture}),'stage',undefined,d.mark));d.capture();assert.deepEqual(d.snapshot(),{version:1,failedStage:'provider-execution'});assert.ok(!JSON.stringify(d.snapshot()).includes('SECRET'));
});

test('post-read validation and readiness timeout use snapshot-validation diagnostics',async t=>{
 for(const invalid of [false,true]){
  const f=fixture(t),d=createOffDiagnostics();let restarted=false;
  const fetchImpl=async(url,r)=>{
   const response=await f.fetcher(url,r);
   if(url.endsWith('/_deploy/restart'))restarted=true;
   if(restarted&&url.endsWith('/_health'))return json({version:invalid?'SECRET':'1.3.0+'+P.revision});
   if(restarted&&url.endsWith('/_deploy/status')&&!invalid){const body=await response.json();body.current=offImage(account,P.rollback);return json(body);}
   return response;
  };
  await assert.rejects(f.run(f.make({fetchImpl,onStage:d.mark,onFailure:d.capture}),'stage',undefined,d.mark));d.capture();
  assert.deepEqual(d.snapshot(),{version:1,failedStage:'snapshot-validation'});assert.ok(!JSON.stringify(d.snapshot()).includes('SECRET'));
  assert.equal(f.events.filter(e=>e[0]==='POST'&&e[1].endsWith('/restart')).length,1);
 }
});
