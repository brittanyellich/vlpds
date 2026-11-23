// Canonical owner-only temporary roots on Linux and macOS.
import{mkdtemp,realpath,chmod}from'node:fs/promises';
import{tmpdir}from'node:os';import{join}from'node:path';
export async function privateTemporaryDirectory(prefix){
 if(!/^exp710-[a-z-]+-$/.test(prefix))throw Error('Temporary prefix refused');
 const root=await realpath(tmpdir());const directory=await mkdtemp(join(root,prefix));
 await chmod(directory,0o700);return directory;
}
