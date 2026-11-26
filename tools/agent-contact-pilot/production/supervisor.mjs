// Opt-in image entrypoint only. Default image still runs vlpds directly.
import {spawn,fork} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';import {join} from 'node:path';
process.umask(0o077);
let directory,bridge,pds,stopping=false;
const cleanup=()=>{if(directory)rmSync(directory,{recursive:true,force:true});};
function stop(signal='SIGTERM'){if(stopping)return;stopping=true;if(pds)pds.kill(signal);else if(bridge)bridge.kill(signal);else{cleanup();process.exit(1);}}
for(const s of ['SIGINT','SIGTERM'])process.once(s,()=>stop(s));
async function main(){
 const env={...process.env};const enabled=env.VLPDS_AGENT_A2A_ENABLED==='true';
 const key=env.VLPDS_AGENT_BRIDGE_KEY,token=env.VLPDS_AGENT_KODY_TOKEN;
 for(const name of ['VLPDS_AGENT_BRIDGE_KEY','VLPDS_AGENT_KODY_TOKEN']){delete env[name];delete process.env[name];}
 // OFF must never inherit a stale native mount from an earlier launch.
 delete env.VLPDS_AGENT_A2A_CONFIG;
 if(enabled){
  const consent=env.VLPDS_AGENT_A2A_REQUIRE_OWNER_CONSENT;
  if(consent!==undefined&&consent!=='true'&&consent!=='false')throw new Error('Invalid owner consent policy');
  if(!/^[a-f0-9]{64}$/.test(key??'')||!token?.startsWith('kody_at_')||env.VLPDS_AGENT_A2A_CALLER!=='did:plc:vsgwub3c3pupqt3yhxfmecma')throw new Error('Explicit native agent setup required');
  const signedCard=env.VLPDS_AGENT_A2A_SIGNED_CARD,cardPin=env.VLPDS_AGENT_A2A_CARD_KEY;
  if(!signedCard||Buffer.byteLength(signedCard)>8192||!cardPin?.startsWith('z')||cardPin.length>128)throw new Error('Production signed Card required');
  JSON.parse(signedCard);
  directory=mkdtempSync(join(tmpdir(),'vlpds-agent-'));
  const keyFile=join(directory,'bridge-key'),tokenFile=join(directory,'profile-token');
  writeFileSync(keyFile,key,{mode:0o600});writeFileSync(tokenFile,token,{mode:0o600});
  const cardFile=join(directory,'signed-card.json');writeFileSync(cardFile,signedCard,{mode:0o600});
  const cfg=join(directory,'native.json');writeFileSync(cfg,JSON.stringify({enabled:true,require_owner_consent:consent==='true',caller_did:env.VLPDS_AGENT_A2A_CALLER,bridge_origin:'http://127.0.0.1:9099',bridge_key_file:keyFile,decision_capacity:Number(env.VLPDS_AGENT_A2A_CAPACITY??'1000'),signed_card_file:cardFile,card_key_multibase:cardPin}),{mode:0o600});env.VLPDS_AGENT_A2A_CONFIG=cfg;
  const bridgeConfig=join(directory,'bridge.json');writeFileSync(bridgeConfig,JSON.stringify({port:9099,keyFile,tokenFile,cliEntry:'/opt/agent-contact-pilot/production/a2a-profile-runtime/node_modules/@kodycodes/cli/dist/bin.js',home:'/opt/agent-home'}),{mode:0o600});
  bridge=fork(new URL('./run-bridge.mjs',import.meta.url),[bridgeConfig],{env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/opt/agent-home'},stdio:['ignore','ignore','inherit','ipc']});
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Bridge readiness deadline')),10000);bridge.once('message',m=>{if(m?.ready===true){clearTimeout(timer);resolve();}else reject(new Error('Bridge readiness refused'));});bridge.once('exit',()=>{clearTimeout(timer);reject(new Error('Bridge exited'));});});
 }
 pds=spawn('/usr/local/bin/vlpds',process.argv.slice(2),{env,stdio:'inherit'});
 pds.once('error',()=>{console.error('Native PDS startup failed');if(bridge)bridge.kill();cleanup();process.exit(1);});
 pds.once('exit',(code)=>{if(bridge&&bridge.exitCode===null&&bridge.signalCode===null){bridge.once('exit',()=>{cleanup();process.exit(code??1);});bridge.kill('SIGTERM');setTimeout(()=>bridge.kill('SIGKILL'),70000).unref();}else{cleanup();process.exit(code??1);}});
 if(bridge)bridge.once('exit',()=>{if(!stopping)stop();});
}
main().catch(()=>{console.error('Native agent startup refused');if(bridge)bridge.kill();cleanup();process.exit(1);});
