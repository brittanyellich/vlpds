// Read-only GitHub observation + structural receipt verification. No dispatch API.
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {PILOT} from '../../deploy/cloudflare/scripts/pilot-activation-plan.mjs';
const REPO='brittanyellich/vlpds',WORKFLOW='.github/workflows/cloudflare-agent-pilot.yml';
const fail=()=>{throw new Error('Rollout proof refused');};
export function childBytes(command,args,{input,signal,maxBytes=65536,timeoutMs=15000}={}){
 return new Promise((resolve,reject)=>{
  const child=spawn(command,args,{stdio:['pipe','pipe','pipe'],detached:process.platform!=='win32'});let bytes=0,parts=[],failed=false,timer,killTimer;
  const kill=kind=>{try{if(process.platform!=='win32'&&child.pid)process.kill(-child.pid,kind);else child.kill(kind);}catch{/* already exited */}};
  const refuse=()=>{if(failed)return;failed=true;clearTimeout(timer);kill('SIGTERM');killTimer=setTimeout(()=>{kill('SIGKILL');reject(new Error('Read-only adapter unavailable'));},200);};
  timer=setTimeout(refuse,timeoutMs);signal?.addEventListener('abort',refuse,{once:true});if(signal?.aborted)refuse();
  child.on('error',()=>{refuse();clearTimeout(killTimer);signal?.removeEventListener('abort',refuse);reject(new Error('Read-only adapter unavailable'));});
  child.stdout.on('data',part=>{bytes+=part.length;if(bytes>maxBytes)refuse();else if(!failed)parts.push(part);});
  child.stderr.resume();child.stdin.on('error',()=>{});child.stdin.end(input);
  child.on('close',code=>{clearTimeout(timer);signal?.removeEventListener('abort',refuse);if(code!==0&&!failed)refuse();if(!failed)resolve(Buffer.concat(parts));});
 });
}

export function github(runId,head){
 if(!Number.isSafeInteger(runId)||runId<1||!/^[a-f0-9]{40}$/.test(head))fail();
 const base=`repos/${REPO}/actions/`;
 return {async get(suffix,signal){
  if(![`runs/${runId}`,`runs/${runId}/jobs?per_page=100`,`runs/${runId}/artifacts?per_page=100`].includes(suffix)&&!/^artifacts\/[1-9][0-9]*\/zip$/.test(suffix))fail();
  return childBytes('gh',['api',base+suffix],{signal});
 }};
}
export async function receiptFromZip(bytes,signal){
 if(bytes.length>65536)fail();
 const script="import sys,io,json,zipfile; b=sys.stdin.buffer.read(65537); assert len(b)<=65536; z=zipfile.ZipFile(io.BytesIO(b)); a=z.infolist(); assert len(a)==1 and a[0].filename=='exp710-activation-ready.json' and a[0].file_size<=8192 and not a[0].flag_bits&1; v=z.read(a[0]); assert len(v)<=8192; json.loads(v); sys.stdout.buffer.write(v)";
 return JSON.parse(await childBytes('python3',['-c',script],{input:bytes,signal,maxBytes:8192}));
}
export function verifyReceipt(receipt,identity,artifact){
 const expected={version:1,kind:'exp710-activation-ready',workerQualificationSha256:'253b25c2baa4983042d803787b60ec0be9838c253b4860761257d0795b345e36',repository:REPO,runId:identity.runId,head:identity.head,digest:PILOT.digest,caller:PILOT.caller,recipient:'did:plc:6tlvgafuonoighfrtpejff5m',profile:PILOT.profile,artifactRevision:PILOT.revision,cardKey:PILOT.cardKey,cardArtifactSha256:'f02d7b8eb0a81f42fa8b3bcde924af57bc5a21bb4f768e9bff782d51fd4db94f',cardPayloadSha256:'0239e2b2eb803c6865f8f7f62203da37eeba64f11ceea25a05a54735d866bf43'};
 if(!receipt||JSON.stringify(Object.keys(receipt).sort())!==JSON.stringify([...Object.keys(expected),'workerVersion','checkedAt','deadline'].sort())||Object.entries(expected).some(([k,v])=>receipt[k]!==v)||!Number.isSafeInteger(receipt.checkedAt)||!Number.isSafeInteger(receipt.deadline)||receipt.deadline>receipt.checkedAt+600||receipt.deadline<=receipt.checkedAt||!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(receipt.workerVersion??''))fail();
 return {...receipt,verified:true,attempt:1,artifactId:artifact.id,artifactDigest:artifact.digest};
}
export async function observeOnce(api,identity,{signal,extract=receiptFromZip,archive=false}={}){
 const decode=async p=>JSON.parse(await api.get(p,signal));
 const run=await decode(`runs/${identity.runId}`);
 if(run.id!==identity.runId||run.repository?.full_name!==REPO||run.head_sha!==identity.head||run.head_branch!=='main'||run.run_attempt!==1||run.event!=='workflow_dispatch'||![WORKFLOW,WORKFLOW+'@main'].includes(run.path))fail();
 if(!archive&&['queued','pending'].includes(run.status)&&run.conclusion===null)return null;
 if(!archive&&(run.status!=='in_progress'||run.conclusion!==null))fail();
 if(archive&&(run.status!=='completed'||run.conclusion!=='success'))fail();
 const jobs=await decode(`runs/${identity.runId}/jobs?per_page=100`);if(jobs.total_count!==1||jobs.jobs?.length!==1||jobs.jobs[0].name!=='pilot'||jobs.jobs[0].run_id!==identity.runId||jobs.jobs[0].head_sha!==identity.head)fail();
 const steps=jobs.jobs[0].steps;
 for(const name of ['Activate guarded Otto-only pilot','Publish sanitized activation-ready receipt']){
  const s=steps.filter(x=>x.name===name);if(s.length!==1)fail();if(['queued','pending','in_progress'].includes(s[0].status)&&!archive)return null;if(s[0].status!=='completed'||s[0].conclusion!=='success')fail();
 }
 const list=await decode(`runs/${identity.runId}/artifacts?per_page=100`);if(!Number.isSafeInteger(list.total_count)||list.total_count>100||list.artifacts?.length!==list.total_count)fail();
 const found=list.artifacts.filter(a=>a.name===`exp710-activation-ready-${identity.runId}`);if(found.length===0&&!archive)return null;if(found.length!==1)fail();const a=found[0];
 if(!Number.isSafeInteger(a.id)||a.id<1||a.workflow_run?.id!==identity.runId||a.workflow_run?.head_sha!==identity.head||a.expired!==false||!Number.isSafeInteger(a.size_in_bytes)||a.size_in_bytes<1||a.size_in_bytes>65536||!/^sha256:[a-f0-9]{64}$/.test(a.digest??''))fail();
 // During launch acceptance, unrelated artifacts indicate a changed workflow.
 if(!archive&&list.total_count!==1)fail();
 const bytes=await api.get(`artifacts/${a.id}/zip`,signal);if(bytes.length!==a.size_in_bytes||'sha256:'+createHash('sha256').update(bytes).digest('hex')!==a.digest)fail();
 return verifyReceipt(await extract(bytes,signal),identity,a);
}
export async function watchReceipt(api,identity,{signal,intervalMs=1000,maxWaitMs=180000,now=()=>performance.now(),...options}={}){
 const start=now();while(now()-start<maxWaitMs){signal?.throwIfAborted();const result=await observeOnce(api,identity,{...options,signal});if(result)return result;await delay(intervalMs,undefined,{signal});}throw new Error('Receipt observation timed out');
}
