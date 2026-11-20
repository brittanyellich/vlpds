import {createHash} from 'node:crypto';
import {PILOT} from './pilot-activation-plan.mjs';
const AGENT='did:plc:6tlvgafuonoighfrtpejff5m';
const DID_URL='https://plc.directory/'+AGENT;
const fixedPublic='https://pds.crate.social';
export const CARD_PATH='/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/.well-known/agent-card.json';
export class ProviderPending extends Error {}
const safeError=()=>new Error('Pilot provider gate failed');
export class PilotProvider {
 constructor({account,cfToken,deployToken,fetchImpl,now=()=>Math.floor(Date.now()/1000)}) {
  if(!/^[a-f0-9]{32}$/.test(account??'') || !/^[A-Za-z0-9_-]{20,256}$/.test(cfToken??'') || !/^[a-f0-9]{64}$/.test(deployToken??'') || typeof fetchImpl!=='function')throw safeError();
  Object.assign(this,{account,cfToken,deployToken,fetchImpl,now});
  this.image=`registry.cloudflare.com/${account}/vlpds@${PILOT.digest}`;
  this.api=`https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/crate-pds`;
  this.postPhases=new Set();
 }
 async request(url,{method='GET',headers={},limit=262144,body,timeout=15000}={}) {
  let response;try {
   const u=new URL(url);if(u.protocol!=='https:' || u.username || u.password || u.search || u.hash)throw 0;
   const admin=url==='https://admin.crate.social/_deploy/status' && method==='GET' || url==='https://admin.crate.social/_deploy/restart' && method==='POST';
   const cf=method==='GET' && (url===this.api+'/deployments' || url.startsWith(this.api+'/versions/') && /^[a-f0-9-]{36}$/.test(url.slice((this.api+'/versions/').length)));
   const pub=method==='GET' && [DID_URL,fixedPublic+'/xrpc/_health',fixedPublic+'/account/spaces',fixedPublic+'/assets/index-D5JRYEyV.js',fixedPublic+CARD_PATH].includes(url);
   if(!admin&&!cf&&!pub)throw 0;
   const auth=admin?{Authorization:`Bearer ${this.deployToken}`}:cf?{Authorization:`Bearer ${this.cfToken}`} : {};
   response=await this.fetchImpl(url,{method,headers:{'Accept-Encoding':'identity','Cache-Control':'no-store',...headers,...auth},body,redirect:'error',signal:AbortSignal.timeout(timeout)});
   const reader=response.body.getReader(),chunks=[];let size=0;
   try {while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit)throw 0;chunks.push(value);}}finally{await reader.cancel().catch(()=>{});}
   const bytes=Buffer.concat(chunks);return {status:response.status,type:response.headers.get('content-type')?.split(';')[0],bytes};
  }catch(e){if(e instanceof TypeError || ['AbortError','TimeoutError'].includes(e?.name))throw new ProviderPending('Provider unavailable');throw safeError();}finally{await response?.body?.cancel().catch(()=>{});}
 }
 async json(url,options){const r=await this.request(url,options);if([502,503,504].includes(r.status))throw new ProviderPending('Provider pending');if(r.status!==200 || r.type!=='application/json')throw safeError();try{return JSON.parse(r.bytes);}catch{throw safeError();}}
 async currentCardKey(){const d=await this.json(DID_URL,{limit:32768});
  if(d.id!==AGENT || d.deactivated!==undefined && d.deactivated!==false || !Array.isArray(d.verificationMethod) || d.verificationMethod.length>64 || !Array.isArray(d.service) || d.service.length>64)throw safeError();
  const keys=d.verificationMethod.filter(k=>k.id===AGENT+'#card-signing'),pds=d.service.filter(s=>['#atproto_pds',AGENT+'#atproto_pds'].includes(s.id));
  if(keys.length!==1 || keys[0].controller!==AGENT || keys[0].type!=='Multikey' || keys[0].publicKeyMultibase!==PILOT.cardKey || pds.length!==1 || pds[0].type!=='AtprotoPersonalDataServer' || pds[0].serviceEndpoint!==fixedPublic)throw safeError();return PILOT.cardKey;
 }
 async status(){const s=await this.json('https://admin.crate.social/_deploy/status',{limit:4096});if(s.desired!==this.image)throw safeError();if(s.running===false && [null,this.image].includes(s.current))throw new ProviderPending('Container pending');if(s.current!==this.image || s.running!==true)throw safeError();return s;}
 async metadata(){const d=await this.json(this.api+'/deployments');const versions=d?.result?.deployments?.[0]?.versions;
  if(d.success!==true || !Array.isArray(versions) || versions.length!==1 || versions[0].percentage!==100 || !/^[a-f0-9-]{36}$/.test(versions[0].version_id))throw safeError();
  const id=versions[0].version_id,v=await this.json(this.api+'/versions/'+id);
  if(v.success!==true || v.result?.id!==id || !Array.isArray(v.result?.resources?.bindings))throw safeError();
  const scriptEtag=v.result.resources.script?.etag;if(typeof scriptEtag!=='string'||!/^[a-f0-9]{64}$/.test(scriptEtag))throw safeError();
  const bindings=v.result.resources.bindings;if(new Set(bindings.map(x=>x.name)).size!==bindings.length)throw safeError();return {id,bindings,scriptEtag};
 }
 async publicChecks(enabled){const health=await this.json(fixedPublic+'/xrpc/_health',{limit:4096});if(typeof health.version!=='string' || !health.version)throw safeError();
  const ui=await this.request(fixedPublic+'/account/spaces',{limit:131072});if([502,503,504].includes(ui.status))throw new ProviderPending('UI pending');if(ui.status!==200 || ui.type!=='text/html' || !ui.bytes.toString().includes('/assets/index-D5JRYEyV.js'))throw safeError();
  const card=await this.request(fixedPublic+CARD_PATH,{limit:8192});if([502,503,504].includes(card.status) || enabled && card.status===404)throw new ProviderPending('Card pending');if(card.status!==(enabled?200:404))throw safeError();return card;
 }
 async restart(phase){if(!['activate','disable'].includes(phase) || this.postPhases.has(phase))throw safeError();await this.status();this.postPhases.add(phase);
  const r=await this.request('https://admin.crate.social/_deploy/restart',{method:'POST',headers:{'X-Deploy-Image':this.image},limit:4096,timeout:75000});
  let a;try{a=JSON.parse(r.bytes);}catch{throw safeError();}if(r.status!==202 || a.desired!==this.image || a.starting!==true || a.restarted!==true)throw safeError();
 }
}
export function checkBindings(meta,{enabled,baseline,provisioned,card,deadline}) {
 const names=['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'];
 const vars={AGENT_A2A_ENABLED:enabled?'true':'false',AGENT_A2A_RUNTIME:'native-profile-v1'};
 if(enabled)Object.assign(vars,{AGENT_A2A_EXPIRES_AT:String(deadline),AGENT_A2A_CALLER_DID:PILOT.caller,AGENT_A2A_CAPACITY:'1000',AGENT_A2A_SIGNED_CARD_JSON:card,AGENT_A2A_CARD_KEY_MULTIBASE:PILOT.cardKey});
 const agent=meta.bindings.filter(b=>b.name.startsWith('AGENT_A2A_'));
 if(agent.length!==Object.keys(vars).length+(provisioned?2:0))throw safeError();
 for(const b of agent){if(names.includes(b.name)){if(!provisioned||b.type!=='secret_text')throw safeError();}else if(b.type!=='plain_text'||b.text!==vars[b.name]||!Object.hasOwn(vars,b.name))throw safeError();}
 const ordinary=meta.bindings.filter(b=>!b.name.startsWith('AGENT_A2A_')).sort((a,b)=>a.name.localeCompare(b.name));
 const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
 const hash=createHash('sha256').update(JSON.stringify(canonical(ordinary))).digest('hex');
 if(baseline && hash!==baseline)throw safeError();
 return hash;
}
