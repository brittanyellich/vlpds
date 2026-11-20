// Actual bundled Worker and Durable Object admission, no container/native calls.
import assert from 'node:assert/strict';import{readFileSync}from'node:fs';import{Miniflare,convertV4MiniflareOptions}from'miniflare';
const script=readFileSync('.wrangler/runtime-test/index.js','utf8');
const paths=['/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/.well-known/agent-card.json','/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/a2a/v1'];
for(const expiry of[undefined,'malformed','9007199254740992',String(Math.floor(Date.now()/1000)-1)]){
 const bindings={PUBLIC_HOST:'pds.crate.social',HANDLE_DOMAIN:'crate.social',ENABLED:'true',AGENT_A2A_ENABLED:'true',AGENT_A2A_KODY_TOKEN:'kody_at_SYNTHETIC_REMAINS_AFTER_RUNNER_LOSS',...(expiry?{AGENT_A2A_EXPIRES_AT:expiry}:{})};
 const mf=new Miniflare(convertV4MiniflareOptions({workers:[{name:'lease-test',modules:true,script,compatibilityDate:'2026-11-05',compatibilityFlags:['nodejs_compat'],durableObjects:{PDS:{className:'Pds',useSQLite:true}},bindings}]}));
 try{
  const ns=await mf.getDurableObjectNamespace('PDS');const direct=ns.getByName('direct-expired-lease');
  for(const [i,path] of paths.entries())for(let replay=0;replay<2;replay++){
   const options={method:i?'POST':'GET',headers:{Authorization:'Bearer SYNTHETIC_NOT_AUTHENTICATED','Cache-Control':'max-age=3600'},...(i?{body:'{"messageId":"same-cached-synthetic-event"}'}:{})};
   const edge=await mf.dispatchFetch('https://pds.crate.social'+path,options);assert.equal(edge.status,404);await edge.body?.cancel();
   const inner=await direct.fetch('https://pds.crate.social'+path,options);assert.equal(inner.status,404);await inner.body?.cancel();
  }
 }finally{await mf.dispose();}
}
console.log('Compiled edge + DO: expired/missing/malformed/overflow lease Card/POST/replay404 before container/auth; runner absent, bindings remain: PASS');
