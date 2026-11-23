// Local orchestration contract only. No GitHub, Terminal, credential or deploy adapter.
// Production proof verification must retain the reviewed authenticated consumer.
// Lease floor: two15s live checks +60s unlock +two10s HTTP +60s reserve =170s, rounded180.
// Age120 is a candidate bound covering observed54s delivery; every later gate
// rechecks age and lease, so a slow operator can still be refused safely.
export const CANDIDATE_LIMITS=Object.freeze({maxAgeSeconds:120,minLeaseSeconds:180,watchSeconds:180,unlockSeconds:60,liveSeconds:15,requestSeconds:10});
const refuse=code=>Object.assign(new Error(code),{code});
export async function bounded(operation,seconds){
 const abort=new AbortController();let timer;
 try{return await Promise.race([operation(abort.signal),new Promise((_,reject)=>{timer=setTimeout(()=>{abort.abort();reject(refuse('timeout'));},seconds*1000);})]);}
 finally{clearTimeout(timer);abort.abort();}
}
export async function dryRunRollout({identity,clock,claim,events,authenticate,live,terminal,cleanup,limit=bounded}){
 const timing=[];let result='refused',reason='invalid-input',cleanupVerified=false;
 const phase=async(name,fn)=>{const start=clock();try{return await fn();}finally{timing.push({phase:name,milliseconds:Math.round((clock()-start)*1000)});}};
 const gate=proof=>{
  const now=clock();
  if(!proof||proof.runId!==identity.runId||proof.head!==identity.head||proof.attempt!==1||proof.verified!==true||!Number.isSafeInteger(proof.artifactId)||proof.artifactId<1||!/^sha256:[a-f0-9]{64}$/.test(proof.digest??''))throw refuse('proof');
  if(!Number.isSafeInteger(proof.checkedAt)||!Number.isSafeInteger(proof.deadline)||proof.checkedAt>now||proof.deadline>proof.checkedAt+600||now-proof.checkedAt>CANDIDATE_LIMITS.maxAgeSeconds)throw refuse('age');
  if(proof.deadline-now<CANDIDATE_LIMITS.minLeaseSeconds)throw refuse('lease');
 };
 try{
  if(!identity||!Number.isSafeInteger(identity.runId)||identity.runId<1||!/^[a-f0-9]{40}$/.test(identity.head??''))throw refuse('invalid-input');
  // Claim must be atomic and durable before watching, unlocking or sending.
  if(!await claim(identity))throw refuse('duplicate');
  const proof=await phase('receipt',()=>limit(async signal=>{
   // Watch adapter starts before publication, authenticates exact named steps.
   const event=await events.next(signal);if(!event)throw refuse('missing');
   return authenticate(event,identity,signal);
  },CANDIDATE_LIMITS.watchSeconds));
  gate(proof);
  const checkLive=()=>phase('live',()=>limit(async signal=>{if(await live(proof,signal)!==true)throw refuse('live');},CANDIDATE_LIMITS.liveSeconds));
  await checkLive();gate(proof);
  await phase('unlock',()=>limit(signal=>terminal.unlock(signal),CANDIDATE_LIMITS.unlockSeconds));
  gate(proof);await checkLive();gate(proof);
  // Adapter must gate deadline before BOTH HTTP requests. One intended message,
  // then one deliberate same-message retry. Ambiguity never creates a new send.
  let admissions=0;
  const response=await phase('request-and-retry',()=>limit(signal=>{
   const admit=()=>{if(signal.aborted||admissions>=2)throw refuse('response');gate(proof);admissions++;};
   return terminal.requestAndRetry({identity,proof,signal,admit});
  },2*CANDIDATE_LIMITS.requestSeconds));
  if(admissions!==2||response?.expectedResponse!==true||response?.sameMessage!==true||response?.sameResponse!==true||response?.transportRequests!==2)throw refuse('response');
  result='accepted';reason='none';
 }catch(error){reason=['invalid-input','proof','age','lease','duplicate','missing','live','response','timeout'].includes(error?.code)?error.code:'adapter';}
 finally{
  // Observe existing mandatory rollback even on missing proof / operator timeout.
  // Duplicate invocations never acquire cleanup ownership from the real owner.
  if(reason!=='duplicate')try{cleanupVerified=await phase('cleanup',()=>cleanup())===true;}catch{cleanupVerified=false;}
 }
 return {result:result==='accepted'&&cleanupVerified?'verified-complete':'refused',acceptance:result,reason,cleanupVerified,timing};
}
