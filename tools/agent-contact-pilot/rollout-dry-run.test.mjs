import test from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,verify,createHash} from 'node:crypto';
import {dryRunRollout,bounded} from './rollout-dry-run.mjs';
const identity={runId:45063222759,head:'5eb6672f161aa5c3b1a666cf2118690843c40227'};
const {publicKey,privateKey}=generateKeyPairSync('ed25519');
function fixture({delay=54,age,remaining,unlock=10,bad,clean=true,live=true}={}){
 let now=1000,launches=0,unlocks=0,cleanup=0,claimed=false;const payload=JSON.stringify({runId:identity.runId,head:identity.head,attempt:1,checkedAt:1000,deadline:1600});
 const envelope={payload,signature:sign(null,Buffer.from(payload),privateKey),artifactId:42,digest:'sha256:'+createHash('sha256').update(payload).digest('hex')};
 const o={identity,clock:()=>now,claim:async()=>{if(claimed)return false;claimed=true;return true;},events:{next:async()=>{now+=age??delay;return bad==='missing'?null:envelope;}},authenticate:async e=>{
  if(bad==='malformed')throw Error('private input must never be reflected');
  if(bad==='signature')e.signature[0]^=1;
  if(!verify(null,Buffer.from(e.payload),publicKey,e.signature))throw Error('signature refused');
  const p=JSON.parse(e.payload);if(bad==='wrong-run')p.runId++;if(bad==='wrong-head')p.head='b'.repeat(40);if(bad==='attempt')p.attempt=2;
  if(remaining!==undefined)p.deadline=now+remaining;
  return {...p,verified:true,artifactId:e.artifactId,digest:bad==='digest'?'bad':e.digest};},
  live:async()=>{now+=1;return live;},terminal:{unlock:async()=>{unlocks++;now+=unlock;},requestAndRetry:async({proof,admit})=>{launches++;assert.ok(proof.deadline-now>=180);admit();now+=1;admit();now+=1;return {expectedResponse:bad!=='response',sameMessage:true,sameResponse:true,transportRequests:2};}},cleanup:async()=>{cleanup++;return clean;},limit:async(fn,seconds)=>{const start=now;const value=await fn(new AbortController().signal);if(now-start>seconds)throw Object.assign(Error(),{code:'timeout'});return value;}};
 return {o,advance:seconds=>{now+=seconds;},counts:()=>({launches,unlocks,cleanup})};
}
test('observed54s delay verifies proof and direct stub launch without chat relay',async()=>{const f=fixture();const r=await dryRunRollout(f.o);assert.equal(r.result,'verified-complete');assert.deepEqual(f.counts(),{launches:1,unlocks:1,cleanup:1});assert.equal(r.timing[0].milliseconds,54000);});
for(const age of [119,120,121])test(`receipt age boundary ${age}`,async()=>{const f=fixture({age,unlock:0});const r=await dryRunRollout(f.o);assert.equal(r.result,'refused');assert.equal(r.reason,'age');assert.equal(f.counts().launches,0);});
test('age117 admits retry at exact120 after both live checks',async()=>{const f=fixture({age:117,unlock:0});assert.equal((await dryRunRollout(f.o)).result,'verified-complete');});
for(const remaining of [179,180,182,183])test(`remaining lease ${remaining}`,async()=>{const f=fixture({remaining,unlock:0});const r=await dryRunRollout(f.o);assert.equal(r.result,remaining===183?'verified-complete':'refused');});
for(const bad of ['missing','malformed','signature','wrong-run','wrong-head','attempt','digest','response'])test(`refuse ${bad}, still observe cleanup`,async()=>{const f=fixture({bad});const r=await dryRunRollout(f.o);assert.equal(r.result,'refused');assert.equal(f.counts().cleanup,1);assert.ok(!JSON.stringify(r).includes('private input'));});
test('duplicate claim cannot unlock/send or take rollback ownership',async()=>{const f=fixture();await dryRunRollout(f.o);const before=f.counts();const r=await dryRunRollout(f.o);assert.equal(r.reason,'duplicate');assert.deepEqual(f.counts(),before);});
for(const settings of [{unlock:61},{live:false},{clean:false}])test(`failure ${JSON.stringify(settings)}`,async()=>{const f=fixture(settings);const r=await dryRunRollout(f.o);assert.equal(r.result,'refused');assert.equal(f.counts().cleanup,1);});
test('missing publication times out and aborts pending adapter',async()=>{let aborted=false;await assert.rejects(bounded(signal=>new Promise(()=>{signal.addEventListener('abort',()=>{aborted=true;});}),0.002));assert.equal(aborted,true);});
test('watch is registered before event publication; no human relay',async()=>{
 const f=fixture();let registered=false,published=false;
 f.o.events.next=async signal=>{assert.equal(signal.aborted,false);registered=true;return await new Promise(resolve=>setImmediate(()=>{assert.equal(registered,true);published=true;resolve({});}));};
 f.o.authenticate=async()=>({runId:identity.runId,head:identity.head,attempt:1,verified:true,artifactId:42,digest:'sha256:'+'a'.repeat(64),checkedAt:1000,deadline:1600});
 assert.equal((await dryRunRollout(f.o)).result,'verified-complete');assert.equal(published,true);
});
test('cleanup exception cannot report successful completion',async()=>{const f=fixture();f.o.cleanup=async()=>{throw Error('private provider error');};const r=await dryRunRollout(f.o);assert.equal(r.result,'refused');assert.equal(r.cleanupVerified,false);assert.ok(!JSON.stringify(r).includes('private provider'));});
test('phase measurements report orchestration overhead separately from virtual latency',async()=>{
 const samples=[];
 for(let i=0;i<40;i++){const f=fixture();const start=performance.now();const r=await dryRunRollout(f.o);samples.push(performance.now()-start);assert.deepEqual(r.timing.map(t=>t.milliseconds),[54000,1000,10000,1000,2000,0]);}
 samples.sort((a,b)=>a-b);console.log(JSON.stringify({fixtureSamples:samples.length,syntheticPhaseMs:{receipt:54000,liveBefore:1000,unlock:10000,liveAfter:1000,requestAndRetry:2000},localOrchestrationP95Ms:Number(samples[37].toFixed(3)),productionLatencyMeasured:false}));
});

for(const artifactId of [NaN,Infinity,-1,0,1.5,Number.MAX_SAFE_INTEGER+1])test(`invalid artifact id ${artifactId}`,async()=>{const f=fixture();const authenticate=f.o.authenticate;f.o.authenticate=async event=>({...await authenticate(event),artifactId});const r=await dryRunRollout(f.o);assert.equal(r.reason,'proof');assert.equal(f.counts().launches,0);});

test('delayed second request is refused by admission callback',async()=>{const f=fixture();let sends=0;f.o.terminal.requestAndRetry=async({admit})=>{admit();sends++;f.advance(100);admit();sends++;};const r=await dryRunRollout(f.o);assert.equal(r.result,'refused');assert.equal(sends,1);});
