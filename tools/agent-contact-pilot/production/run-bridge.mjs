import {readFileSync,statSync} from 'node:fs';
import {createProfileBridge} from './bridge.mjs';
import {dispatchProfileAssertionProduction,inspectCliEntry} from './a2a-profile-dispatch-production.mjs';
function secret(path,max){const m=statSync(path);if((m.mode&0o077)||!m.isFile()||m.size>max)throw new Error('Private secret file refused');return readFileSync(path,'utf8').trim();}
try{
 process.umask(0o077);const config=JSON.parse(readFileSync(process.argv[2],'utf8'));
 const key=Buffer.from(secret(config.keyFile,65),'hex');const token=secret(config.tokenFile,4096);
 inspectCliEntry(config.cliEntry);
 if(config.port!==9099||key.length!==32||!token.startsWith('kody_at_'))throw new Error('Bridge setup refused');
 const server=createProfileBridge({key,dispatch:()=>dispatchProfileAssertionProduction({token,cliEntry:config.cliEntry,home:config.home})});
 server.listen(config.port,'127.0.0.1',()=>{if(process.send)process.send({ready:true});});
 for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>server.close(()=>process.exit(0)));
}catch{console.error('Private profile bridge startup failed');process.exit(1);}
