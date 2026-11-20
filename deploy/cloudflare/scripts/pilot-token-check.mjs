import{PILOT,normalizeCredentialMetadata}from'./pilot-activation-plan.mjs';
// Authoritative self-introspection binds the SAME candidate bearer to metadata.
// No owner/admin API credential, general token read scope or profile execution.
export async function checkCandidateToken(token,{expected,deadline,now,fetchImpl}) {
 let response;try{
  if(!/^kody_at_[A-Za-z0-9_-]{8,4096}$/.test(token??'') || typeof fetchImpl!=='function')throw 0;
  response=await fetchImpl('https://api.kody.codes/v1/tokens/current',{method:'GET',redirect:'error',signal:AbortSignal.timeout(15000),headers:{Authorization:`Bearer ${token}`,'Accept':'application/json','Accept-Encoding':'identity'}});
  if(response.status!==200 || response.headers.get('content-type')?.split(';')[0]!=='application/json')throw 0;
  const reader=response.body.getReader(),chunks=[];let size=0;
  try{while(true){const{done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384)throw 0;chunks.push(value);}}finally{await reader.cancel().catch(()=>{});}
  const raw=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const fields=['id','name','org_id','org_binding','scopes','status','idle_ttl_seconds','expires_at','max_expires_at','created_via','created_at','last_used_at','rotated_at','revoked_at','profile_id'];
  if(JSON.stringify(Object.keys(raw).sort())!==JSON.stringify(fields.sort()) || typeof raw.name!=='string'||typeof raw.created_via!=='string'||raw.revoked_at!==null||['last_used_at','rotated_at'].some(k=>raw[k]!==null&&typeof raw[k]!=='string'))throw 0;
  const selected=Object.fromEntries(['id','created_at','expires_at','max_expires_at','idle_ttl_seconds','profile_id','org_binding','org_id','scopes','status'].map(k=>[k,raw[k]]));
  const actual=normalizeCredentialMetadata(selected,{now,expectedOrg:PILOT.org});
  for(const k of['id','issuedAt','maxExpiresAt','profileId','orgBinding','idleSeconds','maxSeconds'])if(actual[k]!==expected[k])throw 0;
  if(JSON.stringify(actual.scopes)!==JSON.stringify(expected.scopes)||actual.expiresAt<deadline+30||actual.maxExpiresAt<deadline+30)throw 0;
  return actual;
 }catch{throw new Error('Candidate token introspection refused');}
 finally{await response?.body?.cancel().catch(()=>{});}
}
