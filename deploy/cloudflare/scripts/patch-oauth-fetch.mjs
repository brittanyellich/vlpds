import {readFileSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
// The SDK constructs Request(redirect:error) before invoking our fetch adapter.
// workerd rejects that constructor option. Our adapter rejects every 3xx itself,
// so using manual here preserves the SDK's no-redirect security requirement.
const path=fileURLToPath(import.meta.resolve('@atproto-labs/fetch')).replace(/index\.js$/, 'fetch.js');
const before='return new Request(input, init);';
const after="return new Request(input, { ...init, redirect: 'manual' });";
const source=readFileSync(path,'utf8');
if(source.includes(after)) process.exit(0);
if(source.split(before).length!==2) throw new Error('OAuth fetch compatibility patch no longer matches; review SDK before upgrading');
writeFileSync(path,source.replace(before,after));
