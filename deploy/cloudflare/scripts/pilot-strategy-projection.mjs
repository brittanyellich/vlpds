// No provider access: project only the strategy selected by pinned Wrangler.
import {writeFileSync} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';

const refused=()=>new Error('Strategy projection refused');
export function projectStrategy(bytes,{cliMode}={}) {
 try {
  if(typeof bytes!=='string'||Buffer.byteLength(bytes)>1048576)throw 0;
  const config=JSON.parse(bytes);
  if(!config||typeof config!=='object'||Array.isArray(config))throw 0;
  const objects=config.durable_objects;
  if(objects!==undefined&&(!objects||typeof objects!=='object'||Array.isArray(objects)))throw 0;
  const configured=objects?.code_update_strategy;
  if(configured===null||cliMode===null)throw 0;
  const strategy=cliMode??configured??{mode:'deferred',max_delay:300};
  if(!strategy||typeof strategy!=='object'||Array.isArray(strategy)||!['immediate','deferred'].includes(strategy.mode))throw 0;
  if(Object.keys(strategy).some(k=>!['mode','max_delay'].includes(k)))throw 0;
  if(Object.hasOwn(strategy,'max_delay')) {
   const value=strategy.max_delay;
   if(typeof value!=='number'||!Number.isFinite(value)||value<0||value>86400||Math.abs(value*1000-Math.round(value*1000))>1e-7)throw 0;
  }
  // Wrangler drops a valid max_delay for immediate, and defaults an omitted delay.
  const delay=strategy.mode==='immediate'?null:(strategy.max_delay??300);
  if(delay!==null&&(typeof delay!=='number'||!Number.isFinite(delay)||delay<0||delay>86400||Math.abs(delay*1000-Math.round(delay*1000))>1e-7))throw 0;
  return {source:cliMode!==undefined?'cli':configured!=null?'config':'wrangler-default',mode:strategy.mode,maxDelaySeconds:delay};
 }catch{throw refused();}
}

export function strategyReceipt(env) {
 try {
  if(env.GITHUB_ACTIONS!=='true'||env.GITHUB_REPOSITORY!=='brittanyellich/vlpds'||env.GITHUB_REF!=='refs/heads/main'||
   !/^[a-f0-9]{40}$/.test(env.GITHUB_SHA??'')||!/^[1-9][0-9]{0,19}$/.test(env.GITHUB_RUN_ID??'')||env.GITHUB_RUN_ATTEMPT!=='1')throw 0;
  // The current pilot publish command supplies no strategy CLI override.
  return {version:1,kind:'exp710-strategy-projection',readOnly:true,repo:'brittanyellich/vlpds',head:env.GITHUB_SHA,runId:env.GITHUB_RUN_ID,runAttempt:1,wranglerVersion:'4.158.0',...projectStrategy(env.DEPLOY_CONFIG)};
 }catch{throw refused();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try {
  const receipt=strategyReceipt(process.env);
  if(!isAbsolute(process.env.RUNNER_TEMP??''))throw 0;
  writeFileSync(join(process.env.RUNNER_TEMP,'exp710-strategy-projection.json'),JSON.stringify(receipt),{mode:0o600,flag:'wx'});
  console.log(JSON.stringify(receipt));
 }catch{console.error('Strategy projection refused');process.exitCode=1;}
}
