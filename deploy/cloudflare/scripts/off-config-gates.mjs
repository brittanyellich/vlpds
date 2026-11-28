// Pure shared protected-config predicates. No IO or provider imports.
export const OFF_CONFIG_CATEGORIES=Object.freeze(['protected-json','protected-variable-policy','protected-agent-off-keys','protected-agent-off-enabled','protected-agent-off-runtime']);
const fail=()=>new Error('OFF staging gate refused; reconcile read-only, do not replay');
export function checkProtectedOffConfig(bytes,{onStage=()=>{}}={}){
 onStage('protected-json');const original=JSON.parse(bytes);
 onStage('protected-variable-policy');
 if(original.keep_vars===true)throw fail();
 onStage('protected-agent-off-keys');const agent=Object.entries(original.vars??{}).filter(([k])=>k.startsWith('AGENT_A2A_'));
 if(agent.length!==2)throw fail();
 onStage('protected-agent-off-enabled');
 if(!agent.some(([k,v])=>k==='AGENT_A2A_ENABLED'&&v==='false'))throw fail();
 onStage('protected-agent-off-runtime');
 if(!agent.some(([k,v])=>k==='AGENT_A2A_RUNTIME'&&v==='native-profile-v1'))throw fail();
}
