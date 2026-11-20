// Private fixed profile assertion bridge. No repository fetch/CAR parser.
import { createServer } from 'node:http';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { agentDid, principalDid, skillId } from '../pilot.mjs';
export const challengePath = '/private/agent-profile/challenge';
export const assertionPath = '/private/agent-profile/assert';
const domain = 'atagents/private-profile/v1';
export const digest = body => createHash('sha256').update(body).digest('hex');
export const mac = (key, tuple) => createHmac('sha256', key).update(JSON.stringify(tuple)).digest('hex');
export const challengeMac = (key, boot) => mac(key,[domain,'challenge','GET',challengePath,boot]);
export const requestMac = (key,{boot,timestamp,nonce,body})=>mac(key,[domain,'request','POST',assertionPath,boot,timestamp,nonce,digest(body)]);
export const responseMac = (key,{boot,timestamp,nonce,body,response,status})=>mac(key,[domain,'response','POST',assertionPath,boot,timestamp,nonce,digest(body),status,digest(response)]);
const matches = (a,b)=>typeof a==='string' && /^[a-f0-9]{64}$/.test(a) && timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));

export function createProfileBridge({ key, dispatch, clock = ()=>Math.floor(Date.now()/1000) }) {
  if (!Buffer.isBuffer(key)||key.length!==32||typeof dispatch!=='function') throw new Error('Dedicated bridge key and fixed dispatcher required');
  const boot=randomBytes(32).toString('hex');const nonces=new Map();let busy=false;
  const server=createServer({requestTimeout:5000,headersTimeout:3000},async(req,res)=>{
    const send=(status,value,signature)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store',...(signature?{'x-agent-bridge-signature':signature}:{})});res.end(JSON.stringify(value));};
    if(req.socket.remoteAddress!=='127.0.0.1')return send(403,{error:'Private peer required'});
    if(req.method==='GET'&&req.url===challengePath)return send(200,{boot,signature:challengeMac(key,boot)});
    if(req.method!=='POST'||req.url!==assertionPath)return send(404,{error:'Not found'});
    let rawBody;let signed;
    try {
      for(const name of ['x-agent-bridge-boot','x-agent-bridge-timestamp','x-agent-bridge-nonce','x-agent-bridge-signature']) {
        if(req.rawHeaders.filter((v,i)=>i%2===0&&v.toLowerCase()===name).length!==1)throw new Error('Authentication required');
      }
      const timestamp=req.headers['x-agent-bridge-timestamp'],nonce=req.headers['x-agent-bridge-nonce'];
      if(req.headers['x-agent-bridge-boot']!==boot || !/^\d{10}$/.test(timestamp)||Math.abs(clock()-Number(timestamp))>30 || !/^[a-f0-9]{64}$/.test(nonce))throw new Error('Invalid private freshness');
      if(req.headers['content-type']!=='application/json'||req.headers['content-encoding'])throw new Error('Unencoded JSON required');
      const chunks=[];let size=0;const timer=setTimeout(()=>req.destroy(),4000);
      try{for await(const chunk of req){size+=chunk.length;if(size>1024)throw new Error('Body limit');chunks.push(chunk);}}finally{clearTimeout(timer);}
      rawBody=Buffer.concat(chunks);signed={boot,timestamp,nonce,body:rawBody};
      if(!matches(req.headers['x-agent-bridge-signature'],requestMac(key,signed)))throw new Error('Invalid private signature');
      for(const [n,expiry] of nonces)if(expiry<clock())nonces.delete(n);
      if(nonces.has(nonce)||nonces.size>=4096)throw new Error('Replay or capacity refusal');
      nonces.set(nonce,clock()+61);
      const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(rawBody));
      if(!data||Object.keys(data).sort().join(',')!=='agentDid,eventId,principalDid,skillId'||
         data.agentDid!==agentDid||data.principalDid!==principalDid||data.skillId!==skillId||!/^[a-f0-9]{64}$/.test(data.eventId))throw new Error('Fixed assertion only');
      if(busy)throw new Error('Private dispatcher busy');
      busy=true;let value,status=200;
      try{const result=await dispatch();
        if(result?.kind!=='profile_asserted'||result.profileId!=='prf_642a5cf465fa4528a8f7e075f29557c4'||result.agentDid!==agentDid||result.principalDid!==principalDid)throw new Error('Profile mismatch');
        value={eventId:data.eventId,kind:result.kind,profileId:result.profileId,agentDid,principalDid};
      }catch{status=502;value={eventId:data.eventId,error:'Profile assertion failed'};}finally{busy=false;}
      const response=Buffer.from(JSON.stringify(value));
      send(status,value,responseMac(key,{...signed,response,status}));
    }catch{if(!res.headersSent)send(401,{error:'Private assertion refused'});}
  });
  return server;
}
