// Owned Terminal execution of a pinned CLI snapshot. Never captures terminal I/O.
import{readFile,writeFile,mkdir,rm,realpath,lstat}from'node:fs/promises';
import{join,dirname}from'node:path';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';
import{childBytes}from'./rollout-observer.mjs';import{privateDirectory,verifiedLauncherPlan}from'./rollout-terminal.mjs';
import{privateTemporaryDirectory}from'./rollout-private-temp.mjs';
const BOOTSTRAP_SHA256='76dd7be12da4896785cf0941711da1cd4c4f94503d4eea1781f87fd8226b16be';
const hash=b=>createHash('sha256').update(b).digest('hex');
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
const receipt={result:'PASS',cardSignatureValid:true,caller:'did:plc:vsgwub3c3pupqt3yhxfmecma',audience:'did:web:pds.crate.social',lxm:'chat.atagents.agent.contact',status:'verified',stableRetry:true};
export async function qualifiedPythonRuntime(python,expectedHash){
 const command=await realpath(python);if(hash(await readFile(command))!==expectedHash)throw Error('Private interpreter refused');
 const environment=await realpath(dirname(dirname(python)));
 const config=await readFile(join(environment,'pyvenv.cfg'),'utf8');
 if(!/^include-system-site-packages\s*=\s*false\s*$/mi.test(config))throw Error('Qualified private venv required');
 const version=(await childBytes(command,['-I','-c','import sys;print(str(sys.version_info.major)+"."+str(sys.version_info.minor))'])).toString().trim();
 if(!/^[0-9]+\.[0-9]+$/.test(version))throw Error('Private Python version refused');
 const dependencies=await realpath(join(environment,'lib','python'+version,'site-packages'));
 return Object.freeze({command,dependencies});
}
export function requireExecutionWindow(proof,now=Math.floor(Date.now()/1000)){
 if(!Number.isSafeInteger(now)||!Number.isSafeInteger(proof?.checkedAt)||!Number.isSafeInteger(proof?.deadline)||now<proof.checkedAt||now-proof.checkedAt>120||proof.deadline>proof.checkedAt+600||proof.deadline-now<180)throw Error('Private execution window refused');
}
export function verifyPrivateCompletion({proof,done,result,unlocked,signal,now=Math.floor(Date.now()/1000)}){
 signal?.throwIfAborted();requireExecutionWindow(proof,now);
 if(done?.exitCode!==0||!unlocked||!result||JSON.stringify(Object.keys(result).sort())!==JSON.stringify(Object.keys(receipt).sort())||Object.entries(receipt).some(([k,v])=>result[k]!==v))throw Error('Private receipt refused');
}
export function verifiedOwnedCleanup(info,processStopped,windowClosed){
 return Boolean(info)&&Number.isSafeInteger(info.pid)&&info.pid>1&&info.pgid===info.pid&&processStopped===true&&windowClosed===true;
}
async function marker(path){
 try{const s=await lstat(path);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)||s.nlink!==1||s.size>1024)throw Error('Private marker refused');return JSON.parse(await readFile(path));}catch(e){if(e.code==='ENOENT')return null;throw e;}
}
const alive=pid=>{try{process.kill(pid,0);return true;}catch(e){if(e.code==='ESRCH')return false;throw e;}};
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function stopProcess(info){
 if(!info)return true;
 const target=info.pgid===info.pid?-info.pid:info.pid;
 const remains=()=>{try{process.kill(target,0);return true;}catch(e){if(e.code==='ESRCH')return false;throw e;}};
 if(remains()){try{process.kill(target,'SIGTERM');}catch(e){if(e.code!=='ESRCH')throw e;}for(let i=0;i<40&&remains();i++)await pause(50);}
 if(remains()){try{process.kill(target,'SIGKILL');}catch(e){if(e.code!=='ESRCH')throw e;}for(let i=0;i<20&&remains();i++)await pause(50);}
 return !remains();
}
export async function executeOwnedPrivateCli({source,python,pins,initSha256,interpreterSha256,identity,output,proof,denyNetwork,onReady,signal,unlockMs=60000}){
 if(process.platform!=='darwin'||typeof denyNetwork!=='boolean'||unlockMs<100||unlockMs>60000)throw Error('Private Terminal unavailable');
 await privateDirectory(dirname(output));requireExecutionWindow(proof);signal?.throwIfAborted();
 const runtime=await qualifiedPythonRuntime(python,interpreterSha256);
 await verifiedLauncherPlan({source,python:runtime.command,pins,identity,output});
 const root=await privateTemporaryDirectory('exp710-private-cli-');const title='EXP710-'+root.split('/').at(-1);let windowId,processInfo,outcome,callbackFailed=false,callback,launchAttempted=false;
 try{
  const snapshot=join(root,'source');await mkdir(snapshot,{mode:0o700});await mkdir(join(snapshot,'portable_agent'),{mode:0o700});
  for(const[name,pin]of Object.entries({...pins,'__init__.py':initSha256})){
   if(!/^(?:otto_readiness|run_otto_acceptance|otto_acceptance_operator|otto_acceptance|service_auth_check|__init__)\.py$/.test(name))throw Error('Private source refused');
   const bytes=await readFile(join(source,'portable_agent',name));if(hash(bytes)!==pin)throw Error('Private source changed');await writeFile(join(snapshot,'portable_agent',name),bytes,{mode:0o600,flag:'wx'});
  }
  const bootstrap=join(root,'bootstrap.py');const bootstrapBytes=await readFile(fileURLToPath(new URL('./private-cli-bootstrap.py',import.meta.url)));if(hash(bootstrapBytes)!==BOOTSTRAP_SHA256)throw Error('Private bootstrap changed');await writeFile(bootstrap,bootstrapBytes,{mode:0o600,flag:'wx'});
  const config=join(root,'config.json');await writeFile(config,JSON.stringify({root,source:snapshot,dependencies:runtime.dependencies,args:[String(identity.runId),identity.head,output]}),{mode:0o600,flag:'wx'});
  requireExecutionWindow(proof);signal?.throwIfAborted();
  const argv=[...(denyNetwork?['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)']:[]),runtime.command,'-I',bootstrap,config];
  const command='printf shell-entered >'+quote(join(root,'shell-entered'))+'; exec '+argv.map(quote).join(' ');
  launchAttempted=true;
  // Create and identify an inert owned tab before submitting any CLI command.
  const reference=(await childBytes('osascript',['-e',`tell application "Terminal"
set launched to do script ""
try
 set custom title of launched to ${JSON.stringify(title)}
 repeat with w in windows
  repeat with t in tabs of w
   if custom title of t is ${JSON.stringify(title)} then return id of w
  end repeat
 end repeat
 error "Owned window unavailable"
on error
 close launched
 error "Owned window unavailable"
end try
end tell`])).toString().trim();
  if(!/^[1-9][0-9]*$/.test(reference)||!Number.isSafeInteger(Number(reference)))throw Error('Owned Terminal reference refused');windowId=Number(reference);
  signal?.throwIfAborted();requireExecutionWindow(proof);
  await childBytes('osascript',['-e',`tell application "Terminal"\nset visible of window id ${windowId} to true\nset index of window id ${windowId} to 1\nactivate\ndo script ${JSON.stringify(command)} in window id ${windowId}\nend tell`]);
  const start=Date.now();let readyAt,unlocked=false;
  for(;;){
   processInfo=processInfo??await marker(join(root,'process.json'));
   if(processInfo&&(!Number.isSafeInteger(processInfo.pid)||processInfo.pid<2||!Number.isSafeInteger(processInfo.pgid)||processInfo.pgid<2))throw Error('Private process identity refused');
   const ready=await marker(join(root,'ready.json'));
   if(ready&&!readyAt){if(ready.phase!=='private-unlock'||ready.echoDisabled!==true)throw Error('Private input refused');readyAt=Date.now();callback=Promise.resolve(onReady?.({runId:identity.runId,head:identity.head,windowId,phase:'private-unlock',echoDisabled:true})).catch(()=>{callbackFailed=true;});}
   const unlock=await marker(join(root,'unlocked.json'));if(unlock){if(unlock.echoRestored!==true)throw Error('Private echo restoration refused');unlocked=true;}
   const done=await marker(join(root,'done.json'));
   if(done){const result=await marker(output);if(callbackFailed)throw Error('Private ready notification refused');verifyPrivateCompletion({proof,done,result,unlocked,signal});outcome={result:'PASS',runId:identity.runId,head:identity.head,receiptVerified:true,echoRestored:true};break;}
   signal?.throwIfAborted();requireExecutionWindow(proof);
   if(callbackFailed||Date.now()-start>180000||(readyAt&&!unlocked&&Date.now()-readyAt>unlockMs))throw Error('Private execution stopped');
   await pause(50);
  }
 }catch{outcome={result:'FAIL',reason:'Private execution stopped; no automatic retry'};}
 finally{
  let processStopped=false,windowClosed=!launchAttempted;
  try{
   if(!windowId&&launchAttempted){const recovered=(await childBytes('osascript',['-e',`tell application "Terminal"
repeat with w in windows
 repeat with t in tabs of w
  if custom title of t is ${JSON.stringify(title)} then return id of w
 end repeat
end repeat
return 0
end tell`])).toString().trim();if(/^[1-9][0-9]*$/.test(recovered)&&Number.isSafeInteger(Number(recovered)))windowId=Number(recovered);}
  }catch{/* unknown ownership remains a cleanup failure */}
  try{processInfo=processInfo??await marker(join(root,'process.json'));if(processInfo&&(!Number.isSafeInteger(processInfo.pid)||processInfo.pid<2||!Number.isSafeInteger(processInfo.pgid)||processInfo.pgid<2))throw Error('Private process refused');processStopped=await stopProcess(processInfo);}catch{/* still attempt owned UI cleanup */}
  try{if(windowId){const exists=await childBytes('osascript',['-e',`tell application "Terminal" to exists window id ${windowId}`]);if(exists.toString().trim()==='true')await childBytes('osascript',['-e',`tell application "Terminal" to close window id ${windowId}`]);windowClosed=(await childBytes('osascript',['-e',`tell application "Terminal" to exists window id ${windowId}`])).toString().trim()==='false';}}catch{/* cleanup ambiguity is never accepted success */}
  outcome??={result:'FAIL'};
  try{outcome.echoRestored=(await marker(join(root,'unlocked.json')))?.echoRestored===true;outcome.privateInputReached=(await marker(join(root,'ready.json')))?.echoDisabled===true;}catch{outcome.result='FAIL';}
  await rm(root,{recursive:true,force:true});outcome.cleanupVerified=verifiedOwnedCleanup(processInfo,processStopped,windowClosed);outcome.ownedWindowClosed=windowClosed;outcome.ownedProcessGroup=Boolean(processInfo)&&processInfo.pid===processInfo.pgid;if(!outcome.cleanupVerified)outcome.result='FAIL';
 }
 return outcome;
}
