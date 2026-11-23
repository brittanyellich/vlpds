// Private launch preparation and inert TTY rehearsal ONLY. No live execution mode.
import {open,mkdir,lstat,readFile,writeFile,chmod,realpath} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {childBytes} from './rollout-observer.mjs';
const FILES=['otto_readiness.py','run_otto_acceptance.py','otto_acceptance_operator.py','otto_acceptance.py','service_auth_check.py'];
export async function privateDirectory(directory){
 if(!isAbsolute(directory))throw Error('Private directory refused');
 const s=await lstat(directory);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)||await realpath(directory)!==directory)throw Error('Private directory refused');
}
export async function claimRun(directory,identity){
 await privateDirectory(directory);if(!Number.isSafeInteger(identity.runId)||identity.runId<1||!/^[a-f0-9]{40}$/.test(identity.head))throw Error('Claim identity refused');
 try{const f=await open(join(directory,`run-${identity.runId}.claim`),'wx',0o600);try{await f.writeFile(JSON.stringify(identity));await f.sync();}finally{await f.close();}return true;}
 catch(e){if(e.code==='EEXIST')return false;throw e;}
}
export async function verifiedLauncherPlan({source,python,pins,identity,output}){
 if(!isAbsolute(source)||!isAbsolute(python)||!isAbsolute(output)||!Number.isSafeInteger(identity.runId)||identity.runId<1||!/^[a-f0-9]{40}$/.test(identity.head))throw Error('Launcher plan refused');
 for(const name of FILES){const data=await readFile(join(source,'portable_agent',name));if(createHash('sha256').update(data).digest('hex')!==pins[name])throw Error('Launcher source refused');}
 const directory=output.slice(0,output.lastIndexOf('/'));await privateDirectory(directory);
 try{await lstat(output);throw Error('Output already exists');}catch(e){if(e.code!=='ENOENT')throw e;}
 // This plan is data for review; rehearsal never executes these arguments.
 return {command:python,args:['-m','portable_agent.run_otto_acceptance',String(identity.runId),identity.head,output],cwd:source,liveExecutionEnabled:false};
}
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
async function runInertTerminal(directory,commandArgs,{terminalApp=false,run=childBytes,fixtureAction}={}){
 await privateDirectory(directory);const output=join(directory,'rehearsal-result.json');
 const start=performance.now();let windowId,outcome;
 try{
  if(terminalApp){
   const command="printf shell-entered >"+quote(join(directory,'shell-entered'))+'; '+commandArgs.map(quote).join(' ')+"; printf shell-exited >"+quote(join(directory,'shell-exited'));
   const apple='tell application "Terminal" to do script '+JSON.stringify(command);
   const reference=(await run('osascript',['-e',apple])).toString().trim();
   const match=/^tab [1-9][0-9]* of window id ([1-9][0-9]*)$/.exec(reference);
   if(!match)throw Error('Owned Terminal reference unavailable');windowId=Number(match[1]);
   if(!Number.isSafeInteger(windowId))throw Error('Owned Terminal reference unavailable');
   let inputHandled=false;
   for(let i=0;i<300;i++){
    if(fixtureAction&&!inputHandled){
     let ready;try{ready=JSON.parse(await readFile(join(directory,'operator-ready.json')));}catch(error){if(error.code!=='ENOENT')throw error;}
     if(ready){
      if(ready.echoDisabled!==true||!Number.isSafeInteger(ready.pid)||ready.pid<2)throw Error('Synthetic private input refused');
      inputHandled=true;
      if(fixtureAction==='input')await run('osascript',['-e',`tell application "Terminal" to do script "SYNTHETIC_ONLY" in window id ${windowId}`]);
      if(fixtureAction==='stop')process.kill(ready.pid,'SIGTERM');
     }
    }
    try{await lstat(output);break;}catch(e){if(e.code!=='ENOENT')throw e;await new Promise(r=>setTimeout(r,50));}
   }
   }else {
   const pty="import os,pty,sys,signal; pid,fd=pty.fork();\nif pid==0: os.execv(sys.argv[1],sys.argv[1:])\ndef stop(*_):\n try: os.killpg(pid,signal.SIGKILL)\n except ProcessLookupError: pass\n sys.exit(1)\nsignal.signal(signal.SIGTERM,stop)\nwhile True:\n try:\n  if not os.read(fd,4096): break\n except OSError: break\nos.close(fd); _,status=os.waitpid(pid,0); sys.exit(os.waitstatus_to_exitcode(status))";
   await run('python3',['-c',pty,...commandArgs]);
  }
  let raw;
  try{raw=await readFile(output);}catch(error){
   if(!windowId||error.code!=='ENOENT')throw error;
   const entered=await lstat(join(directory,'shell-entered')).then(()=>true,()=>false);
   const exited=await lstat(join(directory,'shell-exited')).then(()=>true,()=>false);
   const failureCategory=!entered?'shell-not-entered':!exited?'worker-not-exited':'worker-no-result';
   return {rehearsal:true,tty:false,liveRequests:0,acceptedSynthetic:false,failureCategory,mode:'Terminal.app-inert',shellEntered:entered,shellExited:exited,startupMilliseconds:performance.now()-start};
  }
  const result=JSON.parse(raw);const s=await lstat(output);if(result.rehearsal!==true||result.tty!==true||result.liveRequests!==0||(s.mode&0o077))throw Error('Rehearsal refused');
  outcome={...result,mode:terminalApp?'Terminal.app-inert':'PTY-inert',startupMilliseconds:performance.now()-start};return outcome;
 }finally{if(windowId){
  await run('osascript',['-e',`tell application "Terminal" to close window id ${windowId}`]);
  if(fixtureAction){const exists=await run('osascript',['-e',`tell application "Terminal" to exists window id ${windowId}`]);if(exists.toString().trim()!=='false')throw Error('Owned fixture window retained');if(outcome)outcome.ownedWindowClosed=true;}
 }}
}

export async function rehearseTerminal(directory,options={}){
 await privateDirectory(directory);const worker=join(directory,'rehearsal.mjs'),output=join(directory,'rehearsal-result.json');
 const code="import{writeFileSync}from'node:fs';if(!process.stdin.isTTY)process.exit(2);writeFileSync(process.argv[2],JSON.stringify({rehearsal:true,tty:true,liveRequests:0}),{mode:0o600,flag:'wx'});";
 await writeFile(worker,code,{mode:0o600,flag:'wx'});return runInertTerminal(directory,[process.execPath,worker,output],options);
}
export async function rehearseConsumerFixture(directory,{python,source,pins,fixturePins,bundle,terminalApp=false,fixtureAction,includeCliFixture=false}){
 // Hash the canonical executable, but retain the verified venv invocation path.
 const interpreter=await realpath(python);
 const interpreterBytes=await readFile(interpreter);
 if(!/^[a-f0-9]{64}$/.test(fixturePins?.interpreterSha256??'')||createHash('sha256').update(interpreterBytes).digest('hex')!==fixturePins.interpreterSha256)throw Error('Fixture interpreter refused');
 if(process.platform!=='darwin')throw Error('OS network-denial rehearsal unavailable');
 await verifiedLauncherPlan({source,python:interpreter,pins,identity:{runId:bundle.run.id,head:bundle.run.head_sha},output:join(directory,'never-live.json')});
 if(bundle.rehearsalOnly!==true)throw Error('Fixture mode required');
 for(const name of ['portable_agent/__init__.py','tests/test_otto_acceptance.py']){const bytes=await readFile(join(source,name));if(createHash('sha256').update(bytes).digest('hex')!==fixturePins?.[name])throw Error('Fixture source refused');}
 const input=join(directory,'fixture.json'),output=join(directory,'rehearsal-result.json');
 await writeFile(input,JSON.stringify(bundle),{mode:0o600,flag:'wx'});
 const snapshot=join(directory,'source');await mkdir(snapshot,{mode:0o700});
 await mkdir(join(snapshot,'portable_agent'),{mode:0o700});await mkdir(join(snapshot,'tests'),{mode:0o700});
 // CLI source is included only for the explicitly network-denied executor fixture.
 for(const name of ['otto_readiness.py','otto_acceptance_operator.py','otto_acceptance.py','service_auth_check.py',...(includeCliFixture?['run_otto_acceptance.py']:[])]){
  const bytes=await readFile(join(source,'portable_agent',name));if(createHash('sha256').update(bytes).digest('hex')!==pins[name])throw Error('Snapshot source refused');
  await writeFile(join(snapshot,'portable_agent',name),bytes,{mode:0o600,flag:'wx'});
 }
 for(const name of ['portable_agent/__init__.py','tests/test_otto_acceptance.py']){
  const bytes=await readFile(join(source,name));if(createHash('sha256').update(bytes).digest('hex')!==fixturePins[name])throw Error('Snapshot fixture refused');
  await writeFile(join(snapshot,name),bytes,{mode:0o600,flag:'wx'});
 }
 const worker=join(directory,'consumer-fixture-worker.py');
 const workerBytes=await readFile(fileURLToPath(new URL('./consumer-fixture-worker.py',import.meta.url)));
 if(createHash('sha256').update(workerBytes).digest('hex')!==fixturePins?.['consumer-fixture-worker.py'])throw Error('Fixture worker refused');
 await writeFile(worker,workerBytes,{mode:0o600,flag:'wx'});
 const bootstrap=join(directory,'fixture-bootstrap.py');
 const code="import os,sys,json,pathlib; worker=sys.argv[1]; output=sys.argv[-1]; sys.argv=sys.argv[1:]\ntry:\n exec(compile(pathlib.Path(worker).read_text(),worker,'exec'),{'__name__':'__main__','__file__':worker})\nexcept BaseException as error:\n category='import' if isinstance(error,ImportError) else 'permission' if isinstance(error,PermissionError) else 'fixture'\n try:\n  fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n  with os.fdopen(fd,'w') as f: json.dump({'rehearsal':True,'tty':sys.stdin.isatty(),'liveRequests':0,'acceptedSynthetic':False,'failureCategory':category},f)\n except FileExistsError: pass";
 await writeFile(bootstrap,code,{mode:0o600,flag:'wx'});
 return runInertTerminal(directory,['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)',python,'-I',bootstrap,worker,snapshot,input,output],{terminalApp,fixtureAction});
}
