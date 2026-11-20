import test from 'node:test';import assert from 'node:assert/strict';
import {agentEnvironment,runtimeEntrypoint,runtimeArgs} from '../src/runtime.ts';
test('agent opt-in selects supervisor and requires separate caller/secret configuration',()=>{
 assert.deepEqual(agentEnvironment({}),{});assert.deepEqual(runtimeEntrypoint(),['/usr/bin/tini','--','vlpds',...runtimeArgs]);
 assert.throws(()=>agentEnvironment({AGENT_A2A_ENABLED:'true'}),/Production signed Card required/);
 const config={AGENT_A2A_ENABLED:'true',AGENT_A2A_RUNTIME:'native-profile-v1',AGENT_A2A_SIGNED_CARD_JSON:'{"signatures":[]}',AGENT_A2A_CARD_KEY_MULTIBASE:'zSyntheticPublicPin',AGENT_A2A_CALLER_DID:'did:plc:vsgwub3c3pupqt3yhxfmecma',AGENT_A2A_BRIDGE_KEY:'a'.repeat(64),AGENT_A2A_KODY_TOKEN:'kody_at_synthetic_fixture'};
 const env=agentEnvironment(config);assert.equal(env.VLPDS_AGENT_A2A_ENABLED,'true');assert.equal(env.VLPDS_AGENT_A2A_CAPACITY,'1000');
 assert.equal(runtimeEntrypoint(true)[2],'/usr/local/bin/node');assert.ok(runtimeEntrypoint(true)[3].endsWith('/supervisor.mjs'));
 for(const change of [{AGENT_A2A_CALLER_DID:'did:plc:other'},{AGENT_A2A_CAPACITY:'100001'},{AGENT_A2A_BRIDGE_KEY:'invalid'}])assert.throws(()=>agentEnvironment({...config,...change}));
});
