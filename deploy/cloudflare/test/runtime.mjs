import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
const mf=new Miniflare(convertV4MiniflareOptions({workers:[{name:"operator-test",modules:true,script:readFileSync('.wrangler/runtime-test/index.js','utf8'),compatibilityDate:'2026-11-05',compatibilityFlags:['nodejs_compat'],durableObjects:{PDS:{className:'Pds',useSQLite:true}},bindings:{ADMIN_HOST:'admin.crate.social',OPERATOR_DID:'did:plc:4hodhjl2kposuchzvpiviwps',ADMIN_TOKEN:'test-token',PUBLIC_HOST:'pds.crate.social',HANDLE_DOMAIN:'crate.social',ENABLED:'true'}}]}));
try {
 for(const [path,method,status] of [['/operator/client-metadata.json','GET',200],['/','GET',200],['/xrpc/vlpds.admin.getClusterStatus','GET',401]]){
  const r=await mf.dispatchFetch('https://admin.crate.social'+path,{method});
  assert.equal(r.status,status);
  await r.body?.cancel();
  console.log(path, r.status);
 }
 if(process.env.OPERATOR_LIVE_TEST==='1') {
  const r=await mf.dispatchFetch('https://admin.crate.social/operator/login',{method:'POST',headers:{origin:'https://admin.crate.social','sec-fetch-site':'same-origin'},redirect:'manual'});
  assert.equal(r.status,303);
  console.log('OAuth initiation passed');
 }
} finally {await mf.dispose()}
