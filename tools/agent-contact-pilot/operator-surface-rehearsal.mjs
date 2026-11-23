import{privateTemporaryDirectory}from'./rollout-private-temp.mjs';
// Automated synthetic operator presentation. Never read/capture terminal contents.
import{mkdtemp,chmod,writeFile,readFile,rm,realpath}from'node:fs/promises';
import{join}from'node:path';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';
import{childBytes}from'./rollout-observer.mjs';
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
export async function operatorSurfaceRehearsal({python,interpreterSha256,provideInput=true,shellMarkers=true}){
 const expectedInput=provideInput;const binary=await realpath(python);if(createHash('sha256').update(await readFile(binary)).digest('hex')!==interpreterSha256)throw Error('Interpreter refused');
 const root=await privateTemporaryDirectory('exp710-operator-surface-');await chmod(root,0o700);let windowId;const start=performance.now();
 try{
  const worker=join(root,'surface.py');await writeFile(worker,await readFile(fileURLToPath(new URL('./operator-surface-fixture.py',import.meta.url))),{mode:0o600,flag:'wx'});
  const command=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)',python,'-I',worker,root,provideInput?'5':'0.5'].map(quote).join(' ');
  const wrapped=shellMarkers?'printf entered >'+quote(join(root,'shell-entered'))+'; '+command+'; printf exited >'+quote(join(root,'shell-exited')):command;
  const reference=(await childBytes('osascript',['-e','tell application "Terminal" to do script '+JSON.stringify(wrapped)])).toString().trim();
  const match=/^tab [1-9][0-9]* of window id ([1-9][0-9]*)$/.exec(reference);if(!match)throw Error('Owned window unavailable');windowId=Number(match[1]);
  // Show only the explicitly owned synthetic window. No settings changes.
  const shown=await childBytes('osascript',['-e',`tell application "Terminal"\n set visible of window id ${windowId} to true\n set index of window id ${windowId} to 1\n activate\n return visible of window id ${windowId}\nend tell`]);
  let ready,result;for(let i=0;i<140;i++){
   if(!ready)try{ready=JSON.parse(await readFile(join(root,'surface-ready.json')));}catch{}
   if(ready&&provideInput){
    if(!ready.echoDisabled||Date.now()/1000>ready.deadline-0.5)throw Error('Synthetic input window unavailable');
    await childBytes('osascript',['-e',`tell application "Terminal" to do script "SYNTHETIC_ONLY" in window id ${windowId}`]);provideInput=false;
   }
   try{result=JSON.parse(await readFile(join(root,'surface-result.json')));break;}catch{}
   await new Promise(r=>setTimeout(r,50));
  }
  if(!result)return{synthetic:true,result:'no-worker-result',windowVisible:shown.toString().trim()==='true',shellMarkers,elapsedMilliseconds:performance.now()-start};
  return{...result,result:result.echoDisabled&&result.echoRestored&&result.networkDenied&&(expectedInput?result.inputMatched&&!result.timedOut:result.timedOut&&!result.inputMatched)?'qualified':'refused',windowVisible:shown.toString().trim()==='true',shellMarkers,elapsedMilliseconds:performance.now()-start};
 }finally{try{if(windowId)await childBytes('osascript',['-e',`tell application "Terminal" to close window id ${windowId}`]);}finally{await rm(root,{recursive:true,force:true});}}
}
