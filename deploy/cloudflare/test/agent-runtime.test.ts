import test from 'node:test';import assert from 'node:assert/strict';
import {agentEnabled,agentEnvironment,runtimeEntrypoint,runtimeArgs} from '../src/runtime.ts';
test('agent opt-in selects supervisor and requires separate caller/secret configuration',()=>{
 assert.deepEqual(agentEnvironment({}),{});assert.deepEqual(runtimeEntrypoint(),['/usr/bin/tini','--','vlpds',...runtimeArgs]);
 assert.throws(()=>agentEnvironment({AGENT_A2A_ENABLED:'true',AGENT_A2A_EXPIRES_AT:String(Math.floor(Date.now()/1000)+599)}),/Production signed Card required/);
 const config={AGENT_A2A_ENABLED:'true',AGENT_A2A_EXPIRES_AT:String(Math.floor(Date.now()/1000)+599),AGENT_A2A_RUNTIME:'native-profile-v1',AGENT_A2A_SIGNED_CARD_JSON:'{"signatures":[]}',AGENT_A2A_CARD_KEY_MULTIBASE:'zSyntheticPublicPin',AGENT_A2A_CALLER_DID:'did:plc:vsgwub3c3pupqt3yhxfmecma',AGENT_A2A_BRIDGE_KEY:'a'.repeat(64),AGENT_A2A_KODY_TOKEN:'kody_at_synthetic_fixture'};
 const env=agentEnvironment(config);assert.equal(env.VLPDS_AGENT_A2A_ENABLED,'true');assert.equal(env.VLPDS_AGENT_A2A_CAPACITY,'1000');
 assert.equal(runtimeEntrypoint(true)[2],'/usr/local/bin/node');assert.ok(runtimeEntrypoint(true)[3].endsWith('/supervisor.mjs'));
 for(const change of [{AGENT_A2A_CALLER_DID:'did:plc:other'},{AGENT_A2A_CAPACITY:'100001'},{AGENT_A2A_BRIDGE_KEY:'invalid'}])assert.throws(()=>agentEnvironment({...config,...change}));
});

test('fixed lease closes new admission at exact boundary without runner or token-use renewal',()=>{
 const now=1800000000,env={AGENT_A2A_ENABLED:'true',AGENT_A2A_EXPIRES_AT:String(now+600)};
 assert.equal(agentEnabled(env,now),true);assert.equal(agentEnabled(env,now+599),true);
 assert.equal(agentEnabled(env,now+600),false);assert.equal(agentEnabled(env,now+601),false);
 for(const lease of[undefined,'','NaN','Infinity','9007199254740992','1800000600.0','01800000600',String(now+601),String(now-1)])assert.equal(agentEnabled({...env,AGENT_A2A_EXPIRES_AT:lease},now),false);
 for(const time of[NaN,Infinity,-1,now+0.5])assert.equal(agentEnabled(env,time),false);
 const expired={...env,AGENT_A2A_EXPIRES_AT:'1000000000'};
 assert.deepEqual(agentEnvironment(expired),{});assert.equal(runtimeEntrypoint(agentEnabled(expired))[2],'vlpds');
 // Replaying a cached request or using a token never changes the fixed lease.
 for(let i=0;i<3;i++)assert.equal(agentEnabled(env,now+601),false);
});

test('explicit hosted consent option propagates only within the fixed active lease',()=>{
 const base={AGENT_A2A_ENABLED:'true',AGENT_A2A_EXPIRES_AT:String(Math.floor(Date.now()/1000)+599),AGENT_A2A_RUNTIME:'native-profile-v1',AGENT_A2A_SIGNED_CARD_JSON:'{"signatures":[]}',AGENT_A2A_CARD_KEY_MULTIBASE:'zSyntheticPublicPin',AGENT_A2A_CALLER_DID:'did:plc:vsgwub3c3pupqt3yhxfmecma',AGENT_A2A_BRIDGE_KEY:'a'.repeat(64),AGENT_A2A_KODY_TOKEN:'kody_at_synthetic_fixture'};
 for(const value of [undefined,'false','true']){
  const e={...base,AGENT_A2A_REQUIRE_OWNER_CONSENT:value};
  assert.equal(agentEnvironment(e).VLPDS_AGENT_A2A_REQUIRE_OWNER_CONSENT,value??'false');
  assert.deepEqual(agentEnvironment({...e,AGENT_A2A_ENABLED:'false'}),{});
  assert.deepEqual(agentEnvironment({...e,AGENT_A2A_EXPIRES_AT:'1000000000'}),{});
 }
 for(const value of ['TRUE','1','',' true','null']){
  const e={...base,AGENT_A2A_REQUIRE_OWNER_CONSENT:value};
  assert.equal(agentEnabled(e),false);assert.deepEqual(agentEnvironment(e),{});
 }
});
