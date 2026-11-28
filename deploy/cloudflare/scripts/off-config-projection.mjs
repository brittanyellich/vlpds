// Config-only projection: no provider, credentials, subprocess or network imports.
import {writeFileSync} from 'node:fs';
import {isAbsolute,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {checkProtectedOffConfig,OFF_CONFIG_CATEGORIES} from './off-config-gates.mjs';
const fail=()=>new Error('OFF config projection refused');
export function projectOffConfig(bytes){
 // An adapter/input-limit failure is not evidence that a shared config gate failed.
 if(typeof bytes!=='string'||Buffer.byteLength(bytes)>1048576)throw fail();
 let stage='protected-json';
 try{
  checkProtectedOffConfig(bytes,{onStage:value=>{if(!OFF_CONFIG_CATEGORIES.includes(value))throw fail();stage=value;}});
  return {result:'passed',failedStage:null};
 }catch{return {result:'refused',failedStage:stage};}
}
export function offConfigReceipt(env){
 if(env.GITHUB_ACTIONS!=='true'||env.GITHUB_REPOSITORY!=='brittanyellich/vlpds'||env.GITHUB_REF!=='refs/heads/main'||env.GITHUB_EVENT_NAME!=='workflow_dispatch'||env.GITHUB_WORKFLOW!=='Project protected OFF config (read only)'||env.GITHUB_RUN_ATTEMPT!=='1'||env.REVIEWED_HEAD!==env.GITHUB_SHA||!(/^[a-f0-9]{40}$/).test(env.GITHUB_SHA??'')||!(/^[1-9][0-9]{0,19}$/).test(env.GITHUB_RUN_ID??''))throw fail();
 return {version:1,kind:'exp710-off-config-projection',readOnly:true,scope:'protected-off-config-gates',head:env.GITHUB_SHA,run:env.GITHUB_RUN_ID,runAttempt:1,...projectOffConfig(env.DEPLOY_CONFIG),readyForStage:false};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{
  const receipt=offConfigReceipt(process.env);
  if(!isAbsolute(process.env.RUNNER_TEMP??''))throw fail();
  writeFileSync(join(process.env.RUNNER_TEMP,'exp710-off-config-projection.json'),JSON.stringify(receipt),{mode:0o600,flag:'wx'});
  // A refusal is an observed gate, not a transport error. Only fixed fields leave the runner.
 }catch{console.error('OFF config projection refused');process.exitCode=1;}
}
