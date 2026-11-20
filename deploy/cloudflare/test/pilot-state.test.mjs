import test from'node:test';import assert from'node:assert/strict';import{sealState,openState}from'../scripts/pilot-state.mjs';
test('state binds phase/deadline/baseline and identity across steps; mutation rejected',()=>{
 const identity={runId:123,head:'a'.repeat(40)},state={...identity,phase:'active',deadline:1800000600,baseline:'b'.repeat(64)},key='c'.repeat(64),envelope=sealState(state,key);
 assert.deepEqual(openState(envelope,key,identity),state);
 for(const patch of[{phase:'preflight'},{deadline:9999999999},{baseline:'other'},{runId:124}]){const e=JSON.parse(envelope);Object.assign(e.state,patch);assert.throws(()=>openState(JSON.stringify(e),key,identity));}
 assert.throws(()=>openState(envelope,'d'.repeat(64),identity));assert.throws(()=>openState(envelope,key,{...identity,runId:124}));
});
