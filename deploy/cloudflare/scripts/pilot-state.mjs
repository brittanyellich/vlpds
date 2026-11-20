import{createHmac,timingSafeEqual}from'node:crypto';
// Domain separation keeps this local state MAC distinct from deploy bearer use.
// Same-UID/runner compromise can read process secrets; this is not an isolation
// boundary against a compromised Actions host.
const mac=(state,key)=>createHmac('sha256',Buffer.from(key,'hex')).update('EXP710-private-state/v1\n').update(JSON.stringify(state)).digest('hex');
export function sealState(state,key){if(!/^[a-f0-9]{64}$/.test(key??''))throw new Error('State key refused');return JSON.stringify({state,mac:mac(state,key)});}
export function openState(bytes,key,identity){try{if(!/^[a-f0-9]{64}$/.test(key??''))throw 0;const e=JSON.parse(bytes);if(!e.state||!/^[a-f0-9]{64}$/.test(e.mac??'')||!timingSafeEqual(Buffer.from(e.mac,'hex'),Buffer.from(mac(e.state,key),'hex')))throw 0;
 for(const k of Object.keys(identity))if(e.state[k]!==identity[k])throw 0;return e.state;}catch{throw new Error('Pilot state integrity refused');}}
