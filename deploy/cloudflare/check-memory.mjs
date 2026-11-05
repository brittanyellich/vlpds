import { spawnSync } from 'node:child_process';
import { runtimeArgs } from './src/runtime.ts';
const [mode, target] = process.argv.slice(2);
if (!['--binary', '--docker'].includes(mode) || !target) {
  console.error('Usage: node check-memory.mjs --binary /path/to/vlpds | --docker image:tag');
  process.exit(2);
}
const r = mode === '--docker'
  ? spawnSync('docker', ['run', '--rm', target, ...runtimeArgs, '--memory-plan'], { stdio: 'inherit' })
  : spawnSync(target, [...runtimeArgs, '--memory-plan'], { stdio: 'inherit' });
if (r.error) console.error(r.error.message);
process.exit(r.status ?? 1);
