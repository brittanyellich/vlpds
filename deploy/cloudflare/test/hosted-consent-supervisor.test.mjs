import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdtempSync,rmSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {stripTypeScriptTypes} from 'node:module';
import {agentEnvironment} from '../src/runtime.ts';

const supervisor=readFileSync(new URL('../../../tools/agent-contact-pilot/production/supervisor.mjs',import.meta.url),'utf8');
const childStub=String.raw`
import {EventEmitter} from 'node:events';
import {readFileSync,statSync} from 'node:fs';
let bridges=0;
function child(){const c=new EventEmitter();c.exitCode=null;c.signalCode=null;c.kill=()=>{c.signalCode='SIGTERM';setImmediate(()=>c.emit('exit',null,'SIGTERM'));};return c;}
export function fork(){bridges++;const c=child();setImmediate(()=>c.emit('message',{ready:true}));return c;}
export function spawn(command,args,{env}){
 if(command!=='/usr/local/bin/vlpds')throw new Error('Unexpected executable');
 const path=env.VLPDS_AGENT_A2A_CONFIG;
 const config=path?JSON.parse(readFileSync(path,'utf8')):null;
 console.log(JSON.stringify({bridges,mounted:!!path,consent:config?.require_owner_consent??null,
  caller:config?.caller_did??null,configMode:path?statSync(path).mode&0o777:null,
  keyMode:config?statSync(config.bridge_key_file).mode&0o777:null,
  secretsAbsent:!('VLPDS_AGENT_BRIDGE_KEY' in env)&&!('VLPDS_AGENT_KODY_TOKEN' in env)}));
 const c=child();setImmediate(()=>{c.exitCode=0;c.emit('exit',0);});return c;
}
`;
function run(env){
 const directory=mkdtempSync(join(tmpdir(),'exp710-supervisor-fixture-'));
 try{
  const stub=join(directory,'child-stub.mjs'),entry=join(directory,'supervisor.mjs');
  writeFileSync(stub,childStub,{mode:0o600});
  assert.equal(supervisor.split("from 'node:child_process'").length,2);
  writeFileSync(entry,supervisor.replace("from 'node:child_process'",`from '${pathToFileURL(stub).href}'`),{mode:0o600});
  const output=execFileSync(process.execPath,[entry,'--help'],{env:{PATH:process.env.PATH,TMPDIR:directory,...env},encoding:'utf8',timeout:5000,stdio:['ignore','pipe','pipe']});
  return JSON.parse(output);
 }finally{
  const remaining=readdirSync(directory).sort();rmSync(directory,{recursive:true,force:true});
  assert.deepEqual(remaining,['child-stub.mjs','supervisor.mjs']);
 }
}
const base={AGENT_A2A_ENABLED:'true',AGENT_A2A_EXPIRES_AT:String(Math.floor(Date.now()/1000)+599),AGENT_A2A_RUNTIME:'native-profile-v1',AGENT_A2A_SIGNED_CARD_JSON:'{"signatures":[]}',AGENT_A2A_CARD_KEY_MULTIBASE:'zSyntheticPublicPin',AGENT_A2A_CALLER_DID:'did:plc:vsgwub3c3pupqt3yhxfmecma',AGENT_A2A_BRIDGE_KEY:'a'.repeat(64),AGENT_A2A_KODY_TOKEN:'kody_at_SYNTHETIC_fixture'};

test('actual supervisor writes Worker-selected consent boolean privately and cleans owned files',()=>{
 for(const value of [undefined,'false','true']){
  const e=agentEnvironment({...base,AGENT_A2A_REQUIRE_OWNER_CONSENT:value});
  const result=run(e);assert.equal(result.consent,value==='true');assert.equal(result.mounted,true);
  assert.equal(result.bridges,1);assert.equal(result.caller,base.AGENT_A2A_CALLER_DID);
  assert.equal(result.configMode,0o600);assert.equal(result.keyMode,0o600);assert.equal(result.secretsAbsent,true);
 }
});
test('OFF/expired Worker launch and direct supervisor OFF discard stale mount without bridge',()=>{
 for(const config of [{...base,AGENT_A2A_ENABLED:'false',AGENT_A2A_REQUIRE_OWNER_CONSENT:'true'}, {...base,AGENT_A2A_EXPIRES_AT:'1000000000'}]){
  const result=run({...agentEnvironment(config),VLPDS_AGENT_A2A_CONFIG:'/must-not-read-stale-config',VLPDS_AGENT_A2A_REQUIRE_OWNER_CONSENT:'true'});
  assert.equal(result.mounted,false);assert.equal(result.bridges,0);assert.equal(result.consent,null);
 }
});
test('invalid direct supervisor consent fails before any child or private configuration',()=>{
 for(const value of ['TRUE','1','',' false']){
  assert.throws(()=>run({...agentEnvironment(base),VLPDS_AGENT_A2A_REQUIRE_OWNER_CONSENT:value}),error=>{
   assert.equal(error.status,1);assert.equal(error.stdout,'');assert.equal(error.stderr,'Native agent startup refused\n');return true;
  });
 }
});


test('actual Worker startup binds environment and entrypoint to one lease snapshot',async()=>{
 let source=readFileSync(new URL('../src/index.ts',import.meta.url),'utf8');
 source=source.replace('import { DurableObject } from "cloudflare:workers";',
  'class DurableObject { constructor(ctx,env){this.ctx=ctx;this.env=env;} }')
  .replaceAll(/from "\.\/(.*?)"/g,(_,path)=>`from "${new URL('../src/'+path,import.meta.url).href}"`);
 const {Pds}=await import('data:text/javascript;base64,'+Buffer.from(stripTypeScriptTypes(source,{mode:'strip'})).toString('base64'));
 const now=1800000000,original=Date.now;
 try{
  for(const [deadline,enabled] of [[now+1,true],[now+601,false]]){
   let captured,calls=0;
   Date.now=()=>1000*(now+calls++);
   const env=new Proxy({...base,ENABLED:'true',CF_ACCOUNT_ID:'a'.repeat(32),AGENT_A2A_CAPACITY:'1000',AGENT_A2A_REQUIRE_OWNER_CONSENT:'true',AGENT_A2A_EXPIRES_AT:String(deadline)},{get:(v,k)=>v[k]??'synthetic'});
   const container={running:false,images:{pds:'synthetic-image'},start:c=>{captured=c;},setInactivityTimeout:async()=>{}};
   const pds=new Pds({container,storage:{setAlarm:async()=>{}}},env);
   await pds.ensureRunning();
   assert.equal(captured.env.VLPDS_AGENT_A2A_ENABLED==='true',enabled);
   assert.equal(captured.entrypoint[2]==='/usr/local/bin/node',enabled);
   assert.equal('VLPDS_AGENT_KODY_TOKEN' in captured.env,enabled);
   assert.equal(captured.env.VLPDS_AGENT_A2A_REQUIRE_OWNER_CONSENT,enabled?'true':undefined);
  }
 }finally{Date.now=original;}
});
