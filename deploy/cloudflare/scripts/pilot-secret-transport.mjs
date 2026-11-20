// Fixed Workers secrets-bulk API used by pinned Wrangler4.158.0. No CLI,
// inherited environment, disk files, redirects, response echo or automatic retry.
export function cloudflareSecretTransport(fetchImpl) {
  if (typeof fetchImpl!=='function') throw new Error('Pilot transport unavailable');
  return async ({stdin,args,childEnv})=>{
    let response;
    const deadline=AbortSignal.timeout(15000);
    try {
      if (JSON.stringify(args)!==JSON.stringify(['secret','bulk','--name','crate-pds']) ||
          !/^[a-f0-9]{32}$/.test(childEnv?.CLOUDFLARE_ACCOUNT_ID??'') ||
          !/^[A-Za-z0-9_-]{20,256}$/.test(childEnv?.CLOUDFLARE_API_TOKEN??'') ||
          Object.keys(childEnv).length!==2 || !Buffer.isBuffer(stdin) || stdin.length>8192) throw 0;
      const values=JSON.parse(stdin.toString('utf8'));
      if (JSON.stringify(Object.keys(values).sort())!==JSON.stringify(['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'])) throw 0;
      if (!/^[a-f0-9]{64}$/.test(values.AGENT_A2A_BRIDGE_KEY) ||
          !/^kody_at_[A-Za-z0-9_-]{8,4096}$/.test(values.AGENT_A2A_KODY_TOKEN)) throw 0;
      const secrets=Object.fromEntries(Object.entries(values).map(([name,text])=>[name,{name,text,type:'secret_text'}]));
      const url=`https://api.cloudflare.com/client/v4/accounts/${childEnv.CLOUDFLARE_ACCOUNT_ID}/workers/scripts/crate-pds/secrets-bulk`;
      response=await fetchImpl(url,{method:'PATCH',redirect:'error',signal:deadline,
        headers:{Authorization:`Bearer ${childEnv.CLOUDFLARE_API_TOKEN}`,'Content-Type':'application/merge-patch+json','Accept-Encoding':'identity'},
        body:JSON.stringify({secrets})});
      if (response.status!==200 || response.headers.get('content-type')?.split(';')[0]!=='application/json') throw 0;
      const reader=response.body.getReader();let size=0;const chunks=[];
      try {while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384)throw 0;chunks.push(value);}}
      finally {await reader.cancel().catch(()=>{});}
      const result=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (result.success!==true) throw 0;
      return true;
    } catch {throw new Error('Pilot secret API failed; no retry');}
    finally {await response?.body?.cancel().catch(()=>{});}
  };
}
