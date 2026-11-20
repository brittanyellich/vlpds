// Test-only deterministic profile fixture, no token/CLI or proof parser.
import {createProfileBridge} from './bridge.mjs';
import {agentDid,principalDid} from '../pilot.mjs';
let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>4096)throw new Error('Fixture input limit');}
const config=JSON.parse(input);
const server=createProfileBridge({key:Buffer.from(config.key,'hex'),dispatch:async()=>({kind:'profile_asserted',profileId:'prf_642a5cf465fa4528a8f7e075f29557c4',agentDid,principalDid})});
server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({origin:`http://127.0.0.1:${server.address().port}`})));
process.once('SIGTERM',()=>server.close(()=>process.exit(0)));
