// Durable, no-replay intent in GitHub Deployments. Actions concurrency and the
// operator write freeze are still required: listing then creating is not CAS.
const REPO='brittanyellich/vlpds';
const refused=()=>new Error('OFF execution journal refused; no replay');
export function createOffJournal({token,head,run,operation,fetchImpl=fetch}){
 // Treat installation tokens as opaque header values, including stateless JWTs.
 // Local bounds/ASCII checks prevent header injection; GitHub authenticates them.
 if(typeof token!=='string'||token.length<20||token.length>8192||/[^\x21-\x7e]/.test(token)||!/^[a-f0-9]{40}$/.test(head??'')||!/^\d{8,20}$/.test(String(run))||!['stage','rollback'].includes(operation))throw refused();
 const task=operation==='stage'?'exp710-off-stage-ea8627d4':'exp710-off-rollback-93724e8b';
 let deployment,claimed=false;
 async function api(path,method='GET',body){
  let response;try{
   response=await fetchImpl(`https://api.github.com/repos/${REPO}/${path}`,{method,redirect:'error',signal:AbortSignal.timeout(15000),headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
   if(response.status!==(method==='POST'?201:200)||response.headers.get('content-encoding')&&!['identity'].includes(response.headers.get('content-encoding')))throw 0;
   const reader=response.body.getReader();let size=0;const parts=[];try{while(true){const r=await reader.read();if(r.done)break;size+=r.value.length;if(size>262144)throw 0;parts.push(r.value);}}finally{await reader.cancel().catch(()=>{});}
   return JSON.parse(Buffer.concat(parts));
  }catch{throw refused();}finally{await response?.body?.cancel().catch(()=>{});}
 }
 return {
  async claim(id){
   if(claimed)throw refused();claimed=true;
   let complete=false;
   for(let page=1;page<=3;page++){
    const list=await api(`deployments?task=${task}&environment=production&per_page=100&page=${page}`);
    if(!Array.isArray(list)||list.some(d=>d.task===task))throw refused();
    if(list.length<100){complete=true;break;}
   }
   if(!complete)throw refused();
   // Persist before any provider mutation. Ambiguous POST is never retried.
   const d=await api('deployments','POST',{ref:head,task,environment:'production',auto_merge:false,required_contexts:[],description:'EXP-710 one-shot OFF transition intent',payload:{version:1,operation,id,run:String(run),candidate:'ea8627d4',rollback:'93724e8b'}});
   if(!Number.isSafeInteger(d?.id)||d.id<=0||d.sha!==head||d.task!==task)throw refused();deployment=d.id;return true;
  },
  async phase(phase){
   if(!deployment||!['upload-attempt','image-prepare-attempt','activate-version-attempt','restore-attempt','restart-attempt','verified','failed'].includes(phase))throw refused();
   await api(`deployments/${deployment}/statuses`,'POST',{state:phase==='verified'?'success':phase==='failed'?'failure':'in_progress',description:`EXP-710 ${phase}`,log_url:`https://github.com/${REPO}/actions/runs/${run}`,auto_inactive:false});
  },
  get id(){return deployment??null;},
 };
}
