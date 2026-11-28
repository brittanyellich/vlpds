import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,lstatSync,rmSync,renameSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {AsyncLocalStorage} from 'node:async_hooks';
import {isDeepStrictEqual} from 'node:util';
import {PilotProvider,ProviderPending,CARD_PATH,checkBindings} from './pilot-provider.mjs';
import {OFF_STAGE as P,offImage,prepareOffStage,qualifyOffTransition,validateOffSnapshot} from './off-staging-plan.mjs';
import {createOffJournal} from './off-staging-journal.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const fail=()=>new Error('OFF transport refused; reconcile read-only, never replay');
const uuid=v=>typeof v==='string'&&/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v);
const PUBLIC='https://pds.crate.social',ADMIN='https://admin.crate.social';
const TREE='a5578cb57829d36f4f2c0bb7f1b507af8783a023';
// Receipt diagnostics are a closed vocabulary, never error messages or values.
export const OFF_STAGE_CATEGORIES=Object.freeze(['execution-context','source-evidence','private-workspace','journal-setup','provider-setup','transition-authority','provider-metadata','runtime-status','container-map','public-health','public-ui','public-card','provider-stability','off-bindings','snapshot-validation','source-prepare','source-identity','source-cleanliness','toolchain','protected-config','protected-account','protected-json','protected-variable-policy','protected-agent-off','protected-agent-off-keys','protected-agent-off-enabled','protected-agent-off-runtime','protected-deployment-contract','config-contract','bundle-build','bundle-artifact','config-live-match','latest-uploaded-version','prepared-source-validation','journal-claim','provider-execution']);
export function createOffDiagnostics(){
 let active='execution-context',failed=null;
 return {mark:stage=>{if(!OFF_STAGE_CATEGORIES.includes(stage))throw new Error('Invalid OFF diagnostic category');if(failed===null)active=stage;},capture:()=>{failed??=active;},snapshot:()=>({version:1,failedStage:failed})};
}

const canonical=value=>JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a<b?-1:a>b?1:0)));
function privateJSON(path,value){writeFileSync(path,JSON.stringify(value),{mode:0o600,flag:'wx'});}
function exactFile(path,limit){const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.size===0||s.size>limit)throw fail();return readFileSync(path);}
export function validateStageConfig(config){
 const allowed=['$schema','name','main','account_id','compatibility_date','compatibility_flags','workers_dev','preview_urls','routes','containers','durable_objects','migrations','vars','observability','keep_vars'];
 if(Object.keys(config).some(k=>!allowed.includes(k))||config.compatibility_date!=='2026-11-05'||JSON.stringify(config.compatibility_flags)!==JSON.stringify(['nodejs_compat'])||config.workers_dev!==false||config.preview_urls!==false||config.keep_vars===true)throw fail();
 if(!isDeepStrictEqual(config.containers,[{class_name:'Pds',scheduling_policy:'durable_object',images:{pds:{image:offImage(config.account_id,P.candidate)}}}]))throw fail();
 const patterns=['pds.crate.social/*','admin.crate.social/*','*.crate.social/.well-known/atproto-did'];
 if(config.routes?.length!==3||new Set(config.routes.map(r=>r.pattern)).size!==3||config.routes.some(r=>!patterns.includes(r.pattern)||r.zone_name!=='crate.social'||Object.keys(r).some(k=>!['pattern','zone_name'].includes(k))))throw fail();
 if(!isDeepStrictEqual(config.durable_objects,{bindings:[{name:'PDS',class_name:'Pds'}]})||!isDeepStrictEqual(config.migrations,[{tag:'v1',new_sqlite_classes:['Pds']}]))throw fail();
 if(config.observability!==undefined&&!isDeepStrictEqual(config.observability,{enabled:false}))throw fail();
}

// Build only the Worker JS bundle, never a Container image. This runs before
// credentials are supplied to Wrangler. Upload exactly these bytes no-bundle.
export function prepareOffBundle({env,root,tmp,execute=execFileSync,onStage=()=>{}}){
 const run=(args,options={})=>execute(args[0],args.slice(1),{cwd:root,stdio:'pipe',timeout:60000,maxBuffer:262144,...options});
 onStage('source-identity');
 if(run(['git','rev-parse','HEAD']).toString().trim()!==P.revision||run(['git','rev-parse','HEAD^{tree}']).toString().trim()!==TREE)throw fail();
 onStage('source-cleanliness');
 run(['git','diff','--exit-code','HEAD','--','.']);
 if(run(['git','ls-files','--others','--exclude-standard','--','.']).toString().trim())throw fail();
 onStage('toolchain');
 if(JSON.parse(exactFile(join(root,'node_modules/wrangler/package.json'),8192)).version!=='4.158.0')throw fail();
 onStage('protected-config');
 const config=prepareOffStage(env,{onStage}),input=join(tmp,'source.json'),bundle=join(tmp,'bundle'),upload=join(tmp,'upload.json');
 onStage('config-contract');validateStageConfig(config);
 config.main=join(root,'src/index.ts');
 onStage('bundle-build');mkdirSync(bundle,{mode:0o700});privateJSON(input,config);
 const safe={PATH:'/usr/bin:/bin',HOME:tmp,TMPDIR:tmp,CI:'true',WRANGLER_SEND_METRICS:'false',WRANGLER_LOG:'error'};
 run([process.execPath,join(root,'node_modules/wrangler/bin/wrangler.js'),'deploy','--dry-run','--config',input,'--outdir',bundle,'--containers-rollout','none'],{env:safe});
 onStage('bundle-artifact');const bytes=exactFile(join(bundle,'index.js'),1048576);
 const frozen={...config,main:join(bundle,'index.js'),no_bundle:true,find_additional_modules:false,upload_source_maps:false};
 privateJSON(upload,frozen);
 const configHash=hash(readFileSync(upload));
 return {revision:P.revision,manifest:P.candidate,ociConfig:P.config,script:hash(bytes),configPath:upload,configHash,bundlePath:join(bundle,'index.js')};
}

export async function moduleHash(response){
 // The caller has already bounded all response bytes. Match the supported
 // content/v2 multipart module interface, not its variable MIME boundary.
 if(response.headers.get('cf-entrypoint')!=='index.js'||!response.headers.get('content-type')?.startsWith('multipart/form-data;'))throw fail();
 const form=await response.formData(),entries=[...form.entries()];
 if(entries.length!==1||entries[0][0]!=='index.js')throw fail();
 const bytes=typeof entries[0][1]==='string'?Buffer.from(entries[0][1]):Buffer.from(await entries[0][1].arrayBuffer());
 if(bytes.length===0||bytes.length>1048576)throw fail();return hash(bytes);
}

// Lower-level transport accepts injected synthetic IO for qualification. The
// only live entry below enforces account/config, GitHub context and proof files.
export function createOffTransport({account,cfToken,deployToken,root,tmp,journal,env,onCheckpoint=()=>{},onStage=()=>{},onFailure=()=>{},expiresAt=Infinity,fetchImpl=fetch,now=()=>Math.floor(Date.now()/1000),sleep=ms=>new Promise(r=>setTimeout(r,ms)),prepare=prepareOffBundle}){
 const api=`https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/crate-pds`;
 let scope,prepared,selectedWorker,selectedScript,target,ordinary,baseline,baselineMeta,postUsed=false,publishUsed=false,restoreUsed=false;
 const context=new AsyncLocalStorage();
 const bounded=async(ms,fn)=>{
  if(scope)throw fail();const controller=new AbortController();scope=controller.signal;
  let timer;try{return await Promise.race([context.run(controller.signal,fn),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(fail());},ms);})]);}finally{clearTimeout(timer);controller.abort();scope=undefined;}
 };
 const scopedFetch=async(url,options)=>{
  const active=context.getStore();if(!active||active.aborted)throw fail();
  const response=await fetchImpl(url,{...options,signal:AbortSignal.any([active,...(options.signal?[options.signal]:[])])});
  if(active.aborted){await response.body?.cancel();throw fail();}
  const encoding=response.headers.get('content-encoding'),length=response.headers.get('content-length');
  if(encoding&&encoding!=='identity'||length!==null&&(!/^\d+$/.test(length)||Number(length)>2097152)){await response.body?.cancel();throw fail();}return response;
 };
 const provider=new PilotProvider({account,cfToken,deployToken,fetchImpl:scopedFetch,now});
 const authority=()=>{if(now()>=expiresAt)throw fail();};
 async function special(path,method='GET',body){
  if(method==='POST')onStage('provider-execution');
  const read=['/content/v2','/versions?per_page=1'].includes(path);
  if(!['/content/v2','/versions?per_page=1','/deployments','/versions?bindings_inherit=strict','@image-prepare'].includes(path)||method!==(read?'GET':'POST'))throw fail();
  let response;try{
   const form=body instanceof FormData;
   const url=path==='@image-prepare'?`https://api.cloudflare.com/client/v4/accounts/${account}/containers/image-preparations`:api+path;
   response=await scopedFetch(url,{method,redirect:'error',signal:AbortSignal.timeout(15000),headers:{Authorization:`Bearer ${cfToken}`,'Accept-Encoding':'identity','Cache-Control':'no-store',...(!form?{'Content-Type':'application/json'}:{})},...(body?{body:form?body:JSON.stringify(body)}:{})});
   if(response.status!==200)throw fail();
   const reader=response.body.getReader(),parts=[];let n=0;try{while(true){const r=await reader.read();if(r.done)break;n+=r.value.length;if(n>2097152)throw fail();parts.push(r.value);}}finally{await reader.cancel().catch(()=>{});}
   return new Response(Buffer.concat(parts),{status:response.status,headers:response.headers});
  }finally{await response?.body?.cancel().catch(()=>{});}
 }
 async function snapshotInternal(){
  onStage('provider-metadata');const first=await provider.metadata();
  onStage('runtime-status');const status=await provider.json(ADMIN+'/_deploy/status',{limit:4096});
  const images=[null,offImage(account,P.candidate),offImage(account,P.rollback)];
  if(!images.slice(1).includes(status.desired)||!images.includes(status.current)||typeof status.running!=='boolean')throw fail();
  onStage('container-map');const version=await provider.json(api+'/versions/'+first.id);
  if(version.success!==true||version.result?.id!==first.id||!isDeepStrictEqual(version.result.resources?.script_runtime?.containers,[{name:'crate-pds-pds',class_name:'Pds',images:{pds:status.desired}}]))throw fail();
  let health={ok:false},uiOk=false,cardStatus=null;
  onStage('public-health');try{const h=await provider.json(PUBLIC+'/xrpc/_health',{limit:4096});health={ok:typeof h.version==='string',version:h.version};}catch(e){if(!(e instanceof ProviderPending))throw e;}
  onStage('public-ui');const ui=await provider.request(PUBLIC+'/account/spaces',{limit:131072});
  if(![200,502,503,504].includes(ui.status))throw fail();uiOk=ui.status===200&&ui.type==='text/html'&&ui.bytes.includes(Buffer.from('/assets/index-D5JRYEyV.js'));
  onStage('public-card');const card=await provider.request(PUBLIC+CARD_PATH,{limit:8192});cardStatus=card.status;if(![404,502,503,504].includes(cardStatus))throw fail();
  let contentHash;
  if(prepared&&first.id===selectedWorker)contentHash=await moduleHash(await special('/content/v2'));
  onStage('provider-stability');const last=await provider.metadata();
  if(JSON.stringify(first)!==JSON.stringify(last))throw fail();
  onStage('off-bindings');baseline??=checkBindings(last,{enabled:false,provisioned:false});baselineMeta=last;
  return {observedAt:now(),meta:last,status,health,uiOk,cardStatus,contentHash};
 }
 const snapshot=(ms=30000)=>bounded(Math.min(30000,ms),snapshotInternal);
 async function latestIs(id){const r=await special('/versions?per_page=1'),v=await r.json();if(v.success!==true||v.result?.items?.length!==1||v.result.items[0].id!==id)throw fail();}
 async function prepareImages(digests){
  await journal.phase('image-prepare-attempt');
  await bounded(95000,async()=>{
   const until=now()+90;
   for(const digest of digests){
    let ready=false;
    while(now()<until){authority();const r=await special('@image-prepare','POST',{image:offImage(account,digest)});const p=await r.json();
     if(p.success!==true)throw fail();if(p.result?.status==='ready'){ready=true;break;}
     if(p.result?.status!=='pending')throw fail();await sleep(Math.min(2000,Math.max(0,(until-now())*1000)));
    }if(!ready)throw fail();
   }
  });
 }
 async function candidateCheckpoint(){
  if(!uuid(selectedWorker)||selectedWorker===P.worker)throw fail();
  const until=now()+30;
  while(now()<until){
   const observed=await snapshot(Math.max(1,(until-now())*1000));
   if(observed.meta.id===P.worker){
    // Only the exact known old deployment is propagation-pending. Unknown
    // versions, code, bindings or images still fail immediately as drift.
    onStage('snapshot-validation');validateOffSnapshot(observed,{account,worker:P.worker,digest:P.rollback,script:P.script,ordinary:baseline,now:now(),healthy:false});
    await sleep(Math.min(2000,Math.max(0,(until-now())*1000)));continue;
   }
   if(observed.meta.id!==selectedWorker||observed.contentHash!==prepared.script)throw fail();selectedScript=observed.meta.scriptEtag;
   onStage('snapshot-validation');validateOffSnapshot(observed,{account,worker:selectedWorker,digest:P.candidate,script:selectedScript,ordinary:baseline,now:now(),healthy:false});
   await onCheckpoint({operation:'stage',worker:selectedWorker,script:selectedScript,ordinary:baseline,digest:P.candidate});return;
  }throw fail();
 }
 return {
  snapshot,
  async prepare(pins){
   if(prepared||pins.revision!==P.revision||pins.manifest!==P.candidate||pins.ociConfig!==P.config)throw fail();
   onStage('source-prepare');prepared=prepare({env,root,tmp,onStage});
   onStage('config-live-match');const projected=JSON.parse(exactFile(prepared.configPath,262144));
   const liveVars=Object.fromEntries(baselineMeta.bindings.filter(b=>b.type==='plain_text').map(b=>[b.name,b.text]));
   if(canonical(projected.vars??{})!==canonical(liveVars))throw fail();
   onStage('latest-uploaded-version');await bounded(15000,()=>latestIs(P.worker));
   return {...pins,script:prepared.script};
  },
  async claim(id){return journal.claim(id);},
  async publish(proof){
   if(publishUsed||!prepared||proof.script!==prepared.script||hash(exactFile(prepared.bundlePath,1048576))!==prepared.script||hash(exactFile(prepared.configPath,262144))!==prepared.configHash)throw fail();publishUsed=true;
   await journal.phase('upload-attempt');
   const immediatelyBefore=await snapshot();
   onStage('snapshot-validation');validateOffSnapshot(immediatelyBefore,{account,worker:P.worker,digest:P.rollback,script:P.script,ordinary:baseline,now:now()});authority();
   target=P.candidate;
   try{
    // Wrangler's rollout=none preserves the old image map, while normal deploy
    // also patches non-versioned settings and may retry uploads. Use the same
    // supported multipart/version/deployment interfaces directly, with no retry.
    await prepareImages([P.rollback,P.candidate]);
    const fresh=await snapshot();onStage('snapshot-validation');validateOffSnapshot(fresh,{account,worker:P.worker,digest:P.rollback,script:P.script,ordinary:baseline,now:now()});await bounded(15000,()=>latestIs(P.worker));authority();
    const metadata={main_module:'index.js',compatibility_date:'2026-11-05',compatibility_flags:['nodejs_compat'],
     bindings:fresh.meta.bindings.map(b=>b.type==='plain_text'?{name:b.name,type:'plain_text',text:b.text}:{name:b.name,type:'inherit'}),
     containers:[{name:'crate-pds-pds',class_name:'Pds',images:{pds:offImage(account,P.candidate)}}]};
    const bytes=exactFile(prepared.bundlePath,1048576);if(hash(bytes)!==prepared.script)throw fail();
    const form=new FormData();form.set('metadata',JSON.stringify(metadata));form.set('index.js',new File([bytes],'index.js',{type:'application/javascript+module'}));
    selectedWorker=await bounded(30000,async()=>{authority();const r=await special('/versions?bindings_inherit=strict','POST',form),v=await r.json();if(v.success!==true||!uuid(v.result?.id)||v.result.id===P.worker)throw fail();return v.result.id;});
    await bounded(15000,()=>latestIs(selectedWorker));
    await bounded(15000,async()=>{
     const v=await provider.json(api+'/versions/'+selectedWorker),meta={id:v.result?.id,scriptEtag:v.result?.resources?.script?.etag,bindings:v.result?.resources?.bindings};
     if(v.success!==true||!isDeepStrictEqual(v.result?.resources?.script_runtime?.containers,metadata.containers))throw fail();
     onStage('snapshot-validation');validateOffSnapshot({meta,status:{desired:offImage(account,P.candidate),current:offImage(account,P.rollback),running:true},observedAt:now()},{account,worker:selectedWorker,digest:P.candidate,ordinary:baseline,now:now(),healthy:false});
    });
    await journal.phase('activate-version-attempt');
    const source=await snapshot();onStage('snapshot-validation');validateOffSnapshot(source,{account,worker:P.worker,digest:P.rollback,script:P.script,ordinary:baseline,now:now()});authority();
    await bounded(20000,async()=>{authority();const r=await special('/deployments','POST',{strategy:'percentage',versions:[{version_id:selectedWorker,percentage:100}],code_update_strategy:'immediate'}),d=await r.json();if(d.success!==true||d.result?.strategy!=='percentage'||d.result?.versions?.length!==1||d.result.versions[0].version_id!==selectedWorker||d.result.versions[0].percentage!==100)throw fail();});
   }catch{
    onFailure();
    // No replay and no continuation to restart after ambiguity. One bounded
    // read-only reconciliation may retain a recoverable, byte-verified identity.
    try{if(!uuid(selectedWorker))selectedWorker=(await bounded(15000,()=>provider.metadata())).id;await candidateCheckpoint();}catch{/* no identity invented */}
    throw fail();
   }
   await candidateCheckpoint();
   return {...proof,worker:selectedWorker,scriptEtag:selectedScript};
  },
  async restore(body){
   if(restoreUsed||JSON.stringify(body)!==JSON.stringify({strategy:'percentage',versions:[{version_id:P.worker,percentage:100}],code_update_strategy:'immediate'}))throw fail();restoreUsed=true;
   const source=baselineMeta;await prepareImages([P.rollback]);await journal.phase('restore-attempt');
   await bounded(30000,async()=>{
    const meta=await provider.metadata(),status=await provider.json(ADMIN+'/_deploy/status',{limit:4096});
    onStage('snapshot-validation');validateOffSnapshot({meta,status,observedAt:now()},{account,worker:source.id,digest:P.candidate,script:source.scriptEtag,ordinary:baseline,now:now(),healthy:false});authority();
    const response=await special('/deployments','POST',body);const d=await response.json();if(d.success!==true||d.result?.strategy!=='percentage'||d.result.versions?.length!==1||d.result.versions[0].version_id!==P.worker||d.result.versions[0].percentage!==100)throw fail();
   });
   selectedWorker=P.worker;selectedScript=P.script;target=P.rollback;
   const until=now()+30;
   while(now()<until){
    const s=await snapshot(Math.max(1,(until-now())*1000));
    if(s.meta.id===source.id){onStage('snapshot-validation');validateOffSnapshot(s,{account,worker:source.id,digest:P.candidate,script:source.scriptEtag,ordinary:baseline,now:now(),healthy:false});await sleep(Math.min(2000,Math.max(0,(until-now())*1000)));continue;}
    onStage('snapshot-validation');validateOffSnapshot(s,{account,worker:P.worker,digest:P.rollback,script:P.script,ordinary:baseline,now:now(),healthy:false});return;
   }throw fail();
  },
  async restart(image){
   if(postUsed||image!==offImage(account,target))throw fail();postUsed=true;
   await journal.phase('restart-attempt');
   return bounded(75000,async()=>{
    const meta=await provider.metadata(),s=await provider.json(ADMIN+'/_deploy/status',{limit:4096});
    onStage('snapshot-validation');validateOffSnapshot({meta,status:s,observedAt:now()},{account,worker:selectedWorker,digest:target,script:selectedScript,ordinary:baseline,now:now(),healthy:false});authority();
    onStage('provider-execution');const r=await provider.request(ADMIN+'/_deploy/restart',{method:'POST',headers:{'X-Deploy-Image':image},limit:4096,timeout:75000});
    if(r.type!=='application/json')throw fail();return{status:r.status,body:JSON.parse(r.bytes)};
   });
  },
  async ready(){
   const until=now()+90;
   while(now()<until){
    const s=await snapshot();
    onStage('snapshot-validation');ordinary=validateOffSnapshot(s,{account,worker:selectedWorker,digest:target,script:selectedScript,ordinary,now:now(),healthy:false});
    if(s.status.current===offImage(account,target)&&s.status.running&&s.health.ok&&s.uiOk&&s.cardStatus===404)return s;
    await sleep(Math.min(2000,Math.max(0,(until-now())*1000)));
   }throw fail();
  },
 };
}

export async function runOffStage(env,{fetchImpl=fetch}={}){
 const diagnostics=createOffDiagnostics();
 const report={version:1,kind:'exp710-off-staging',result:'failed',operation:env.OPERATION,run:String(env.GITHUB_RUN_ID),head:env.GITHUB_SHA,manifest:P.candidate,ociConfig:P.config,rollbackWorker:P.worker,rollbackImage:P.rollback,providerWritesAttempted:false};
 let journal,transport,tmp,ownedReceipt=false,sequence=0;
 const receiptPath=join(env.RUNNER_TEMP,'exp710-off-staging-receipt.json');
 const checkpoint=()=>{report.diagnostics=diagnostics.snapshot();if(!ownedReceipt){privateJSON(receiptPath,report);ownedReceipt=true;}else{const next=receiptPath+`.${process.pid}.${sequence++}`;privateJSON(next,report);renameSync(next,receiptPath);}};
 try{
  if(env.GITHUB_REPOSITORY!=='brittanyellich/vlpds'||env.GITHUB_REF!=='refs/heads/main'||env.GITHUB_RUN_ATTEMPT!=='1'||env.GITHUB_EVENT_NAME!=='workflow_dispatch'||env.GITHUB_WORKFLOW!=='Stage qualified agent OFF (manual only)'||env.EXCLUSIVE_WINDOW!=='true'||env.REVIEWED_HEAD!==env.GITHUB_SHA||!['stage','rollback'].includes(env.OPERATION)||!/^[a-f0-9]{40}$/.test(env.GITHUB_SHA??'')||hash(env.CLOUDFLARE_ACCOUNT_ID??'')!==P.accountHash)throw fail();
  diagnostics.mark('source-evidence');const evidence=JSON.parse(exactFile(join(env.RUNNER_TEMP,'exp710-off-evidence.json'),16384));
  if(evidence.manifest!==P.candidate||evidence.ociConfig!==P.config||evidence.accountHash!==P.accountHash||!/^[a-f0-9]{64}$/.test(evidence.executionCodeHash??''))throw fail();
  report.executionCodeHash=evidence.executionCodeHash;checkpoint();
  if(env.OPERATION==='rollback'&&(!uuid(evidence.staged?.worker)||evidence.staged.operation!=='stage'||evidence.staged.digest!==P.candidate))throw fail();
  diagnostics.mark('private-workspace');const privatePath=join(env.RUNNER_TEMP,'exp710-off-private');mkdirSync(privatePath,{mode:0o700});tmp=privatePath;
  diagnostics.mark('journal-setup');journal=createOffJournal({token:env.GH_TOKEN,head:env.GITHUB_SHA,run:env.GITHUB_RUN_ID,operation:env.OPERATION,fetchImpl});
  const proxyJournal={claim:id=>journal.claim(id),phase:async p=>{if(['upload-attempt','image-prepare-attempt','activate-version-attempt','restore-attempt','restart-attempt'].includes(p)){report.providerWritesAttempted=true;checkpoint();}await journal.phase(p);}};
  const now=()=>Math.floor(Date.now()/1000),expiresAt=now()+600,id=hash(`${env.GITHUB_RUN_ID}:${env.OPERATION}`).slice(0,32).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
  diagnostics.mark('provider-setup');transport=createOffTransport({account:env.CLOUDFLARE_ACCOUNT_ID,cfToken:env.CLOUDFLARE_API_TOKEN,deployToken:env.VLPDS_DEPLOY_TOKEN,env:{...env,DEPLOY_TOKEN:env.VLPDS_DEPLOY_TOKEN},root:resolve(env.CANDIDATE_ROOT,'deploy/cloudflare'),tmp,journal:proxyJournal,fetchImpl,expiresAt,onStage:diagnostics.mark,onFailure:diagnostics.capture,onCheckpoint:async recovery=>{report.recovery=recovery;report.journal=journal.id;checkpoint();}});
  const result=await qualifyOffTransition({operation:env.OPERATION,grant:{operation:env.OPERATION,id,candidate:P.candidate,rollbackWorker:P.worker,exclusiveWindow:true,expiresAt},account:env.CLOUDFLARE_ACCOUNT_ID,transport,now,staged:evidence.staged,onStage:diagnostics.mark});
  Object.assign(report,{transition:result,result:'verified',journal:journal.id});await journal.phase('verified');
 }catch{
  diagnostics.capture();report.result='failed';report.journal=journal?.id??null;
  if(journal?.id)try{await journal.phase('failed');}catch{/* receipt still records failed; no replay */}
 }finally{
  if(tmp)rmSync(tmp,{recursive:true,force:true});
  checkpoint();
 }return report;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 process.umask(0o077);try{const report=await runOffStage(process.env);if(report.result!=='verified')throw fail();}catch{console.error('OFF transition not verified; reconcile read-only without replay.');process.exitCode=1;}
}
