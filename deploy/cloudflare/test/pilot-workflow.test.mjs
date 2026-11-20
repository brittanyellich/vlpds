import test from 'node:test';import assert from 'node:assert/strict';import{readFileSync}from'node:fs';import{spawnSync}from'node:child_process';import{fileURLToPath}from'node:url';
const workflow=readFileSync(new URL('../../../.github/workflows/cloudflare-agent-pilot.yml',import.meta.url),'utf8');
test('manual production workflow is serialized, main-only one attempt, fixed steps and cleanup always',()=>{
 assert.match(workflow,/workflow_dispatch:/);assert.match(workflow,/github\.ref == 'refs\/heads\/main' && github\.run_attempt == 1/);assert.match(workflow,/group: crate-pds-cloudflare-production/);assert.match(workflow,/cancel-in-progress: false/);assert.match(workflow,/timeout-minutes: 25/);assert.match(workflow,/persist-credentials: false/);
 assert.match(workflow,/npm test && npm run typecheck && npm run test:runtime/);
 assert.ok(!/docker |npx |npm publish|workflow_call|pull_request:/.test(workflow));
 const steps=workflow.split('    steps:')[1].split(/\n      - /);
 const profileSteps=steps.filter(s=>s.includes('secrets.VLPDS_AGENT_KODY_TOKEN'));assert.equal(profileSteps.length,1);assert.match(profileSteps[0],/pilot-runner\.mjs provision/);
 for(const s of steps.filter(s=>s.includes('npm ci')||s.includes('npm test')||s.includes('uses: actions/')))assert.ok(!s.includes('${{ secrets.'));
 assert.match(steps.find(s=>s.includes('pilot-runner.mjs disable')),/if: always\(\)/);assert.match(steps.find(s=>s.includes('pilot-runner.mjs cleanup')),/if: always\(\)/);
});
test('runner refuses local/invalid invocation before provider or credentials and emits only fixed failure',()=>{
 const r=spawnSync(process.execPath,[fileURLToPath(new URL('../scripts/pilot-runner.mjs',import.meta.url)),'invalid'],{env:{PATH:'/usr/bin:/bin'},encoding:'utf8',timeout:5000});
 assert.equal(r.status,1);assert.deepEqual(JSON.parse(r.stdout),{kind:'exp710-failed',phase:'invalid',reconcile:true});assert.equal(r.stderr,'');
});
