import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,lstatSync} from 'node:fs';
import {join} from 'node:path';
import {PILOT_UPDATE_MODE} from './pilot-update-mode.mjs';
const refused=()=>new Error('Pilot publish acknowledgement unavailable; reconcile read-only');
// Supported Wrangler ND-JSON is independent of log level. Lifecycle must still
// verify authoritative active Worker metadata/config before restart or cleanup.
export function parsePublishAcknowledgement(bytes) {
 try {
  if(!Buffer.isBuffer(bytes)||bytes.length===0||bytes.length>65536)throw 0;
  const lines=new TextDecoder('utf-8',{fatal:true}).decode(bytes).trim().split('\n');if(lines.length!==2)throw 0;
  const session=JSON.parse(lines[0]);
  if(session?.type!=='wrangler-session'||session.version!==1||session.wrangler_version!=='4.158.0')throw 0;
  const e=JSON.parse(lines[1]);
  if(e?.type!=='deploy'||e.version!==1||e.worker_name!=='crate-pds'||typeof e.version_id!=='string'||e.version_id.length!==36||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(e.version_id))throw 0;
  return e.version_id;
 }catch{throw refused();}
}
export function publishPilotWorker({root,tmp,configPath,account,token,execute=execFileSync}) {
 const outputPath=join(tmp,'publish.ndjson');
 try {
  writeFileSync(outputPath,'',{mode:0o600,flag:'wx'});
  execute(process.execPath,[join(root,'node_modules/wrangler/bin/wrangler.js'),'deploy','--name','crate-pds','--config',configPath,'--containers-rollout','none','--durable-objects-code-update-mode',PILOT_UPDATE_MODE],{
   cwd:root,env:{PATH:'/usr/bin:/bin',HOME:tmp,TMPDIR:tmp,CLOUDFLARE_API_TOKEN:token,CLOUDFLARE_ACCOUNT_ID:account,WRANGLER_SEND_METRICS:'false',WRANGLER_LOG:'info',WRANGLER_OUTPUT_FILE_PATH:outputPath},
   stdio:'pipe',maxBuffer:262144,timeout:180000});
  const stat=lstatSync(outputPath);if(!stat.isFile()||stat.size>65536)throw 0;
  return parsePublishAcknowledgement(readFileSync(outputPath));
 }catch{ // A write may have happened; never retry or reveal captured CLI output.
  throw refused();
 }
}
