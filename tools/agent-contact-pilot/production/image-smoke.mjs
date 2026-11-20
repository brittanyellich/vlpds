// Local Docker artifact checks only. Synthetic keys/token are never used online.
import {execFile} from 'node:child_process';import{promisify}from'node:util';
const run=promisify(execFile);const docker=process.env.DOCKER_BIN??'/usr/local/bin/docker';const image=process.argv[2];
if(!image)throw new Error('Pass an explicitly built local image');
const base=['run','--rm','--network','none','--read-only','--tmpfs','/tmp'];
const off=await run(docker,[...base,image,'--help'],{timeout:20000,maxBuffer:1024*1024});
if(!off.stdout.includes('--agent-a2a-config'))throw new Error('Native opt-in missing from artifact');
const on=await run(docker,[...base,'-e','VLPDS_AGENT_A2A_ENABLED=true','-e','VLPDS_AGENT_A2A_CALLER=did:plc:vsgwub3c3pupqt3yhxfmecma','-e','VLPDS_AGENT_BRIDGE_KEY='+'a'.repeat(64),'-e','VLPDS_AGENT_KODY_TOKEN=kody_at_SYNTHETIC_NEVER_VALID','-e','VLPDS_AGENT_A2A_SIGNED_CARD={"test":"startup-help-only-never-served"}','-e','VLPDS_AGENT_A2A_CARD_KEY=zSyntheticPublicPin',image,'--help'],{timeout:20000,maxBuffer:1024*1024});
if(!on.stdout.includes('--agent-a2a-config')||on.stdout.includes('kody_at_SYNTHETIC'))throw new Error('Supervisor artifact refused');
let refused=false;try{await run(docker,[...base,'-e','VLPDS_AGENT_A2A_ENABLED=true',image,'--help'],{timeout:20000,maxBuffer:1024*1024});}catch(e){refused=e.stderr?.includes('Native agent startup refused');}
if(!refused)throw new Error('Incomplete opt-in should refuse startup');
console.log(JSON.stringify({defaultOffHelp:true,optInBridgeReadinessAndNativeHelp:true,incompleteConfigDenied:true,networkDisabled:true,readOnlyRoot:true,realProfileTokenUsed:false,realProfileInvoked:false}));
