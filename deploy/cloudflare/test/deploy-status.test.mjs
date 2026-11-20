import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';

// Exercise the exact inline workflow reader without checkout/actions or network.
const workflow = readFileSync(new URL('../../../.github/workflows/cloudflare-status.yml', import.meta.url), 'utf8');
const block = workflow.split('# BEGIN_STATUS_READER\n')[1].split('# END_STATUS_READER')[0];
const source = block.split('\n').map(line => {
  if (!line.trim()) return '';
  assert.ok(line.startsWith(' '.repeat(10))); return line.slice(10);
}).join('\n');
const account = 'a'.repeat(32);
const image = repo => `registry.cloudflare.com/${account}/${repo}@sha256:${'b'.repeat(64)}`;
const status = {desired:image('vlpds'),current:image('crate-pds-pds-pds'),running:true};
const harness = String.raw`
import contextlib, io, json, ssl, sys, types
p = json.load(sys.stdin)
n = {'__name__':'workflow_reader_test'}
exec(p['source'], n)
calls = []; made = []; closed = []; reads = []
class Response:
    status = p.get('status',200)
    def getheader(self,key,default=None):
        return p.get('headers',{'Content-Type':'application/json'}).get(key,default)
    def read(self,limit):
        assert limit == 4097
        reads.append(limit)
        if p.get('networkError'):
            raise RuntimeError('RAW_BODY_OR_HEADER_MUST_NEVER_APPEAR')
        return (b'\xff' if p.get('invalidUtf8') else p['body'].encode('utf-8'))[:limit]
class Connection:
    def __init__(self,host,port,timeout,context):
        assert host == 'admin.crate.social' and port == 443 and timeout == 10
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        made.append(True)
    def request(self,method,path,headers):
        assert method == 'GET' and path == '/_deploy/status'
        assert headers == {'Authorization':'Bearer '+'c'*64,'Accept':'application/json','Accept-Encoding':'identity'}
        calls.append([method,path])
    def getresponse(self): return Response()
    def close(self): closed.append(True)
result = None; error = None; out = ''; err = ''; alarms = []; code = None
if p.get('main'):
    original = n['read_status']
    n['read_status'] = lambda token: original(token,Connection)
    n['os'] = types.SimpleNamespace(environ={'VLPDS_DEPLOY_TOKEN':'c'*64})
    n['signal'] = types.SimpleNamespace(SIGALRM=14,signal=lambda *_:None,alarm=lambda seconds:alarms.append(seconds))
    stdout,stderr = io.StringIO(),io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr): code = n['main']()
    out,err = stdout.getvalue(),stderr.getvalue()
else:
    try: result = n['read_status'](p.get('token','c'*64),Connection)
    except Exception as e: error = type(e).__name__
print(json.dumps({'result':result,'error':error,'made':len(made),'calls':calls,'closed':len(closed),'reads':len(reads),'out':out,'err':err,'alarms':alarms,'code':code}))
`;
function probe(overrides={}) {
  const child=spawnSync('python3',['-c',harness],{input:JSON.stringify({source,body:JSON.stringify(status),...overrides}),encoding:'utf8',timeout:5000});
  assert.equal(child.status,0,child.stderr); return JSON.parse(child.stdout);
}
test('manual main-only status job has no GitHub permissions, checkout, actions or URL inputs',()=>{
  assert.match(workflow,/permissions: \{\}/); assert.match(workflow,/workflow_dispatch:/);
  assert.match(workflow,/if: github.ref == 'refs\/heads\/main'/); assert.match(workflow,/timeout-minutes: 2/);
  assert.equal((workflow.match(/\$\{\{ secrets\.[A-Z_]+ \}\}/g)??[]).length,1);
  assert.ok(!/^\s+uses:/m.test(workflow)); assert.ok(!/inputs:|_deploy\/restart|workflow_call:/.test(workflow));
});
test('exact HTTPS GET validates then masks account IDs; current may be null',()=>{
  const r=probe();assert.equal(r.error,null);assert.equal(r.made,1);assert.equal(r.closed,1);
  assert.deepEqual(r.calls,[['GET','/_deploy/status']]);assert.equal(r.reads,1);
  assert.deepEqual(r.result,{desired:image('vlpds').replace(account,'<account>'),current:image('crate-pds-pds-pds').replace(account,'<account>'),running:true});
  assert.ok(!JSON.stringify(r.result).includes(account));
  assert.deepEqual(probe({body:JSON.stringify({...status,current:null,running:false})}).result,{desired:r.result.desired,current:null,running:false});
});
test('redirects/errors/encoded or oversized responses are refused without another request',()=>{
  for(const change of [{status:302},{status:500},{headers:{'Content-Type':'text/html'}},{headers:{'Content-Type':'application/json','Content-Encoding':'gzip'}},
    {headers:{'Content-Type':'application/json','Content-Length':'4097'}},{headers:{'Content-Type':'application/json','Content-Length':'-1'}},{body:'x'.repeat(4097)},{invalidUtf8:true}]) {
    const r=probe(change);assert.ok(r.error);assert.equal(r.result,null);assert.equal(r.calls.length,1);assert.equal(r.closed,1);
  }
});
test('schema, duplicate keys, unpinned URLs, output injection and foreign accounts fail closed',()=>{
  const invalid=[{...status,running:1},{...status,extra:'RAW_SECRET'}, {...status,desired:image('vlpds')+'?token=RAW_SECRET'},
    {...status,current:image('vlpds').replace(account,'d'.repeat(32))},{...status,desired:'https://other.invalid/RAW_SECRET'},
    {...status,current:'line\nRAW_SECRET'}];
  for(const body of [...invalid.map(v=>JSON.stringify(v)),'not-json','{"desired":"x","desired":"y","current":null,"running":false}']) {
    const r=probe({body});assert.ok(r.error);assert.equal(r.result,null);
  }
});
test('missing/invalid token is refused before network access',()=>{
  for(const token of [null,'','c'.repeat(63),'C'.repeat(64),'Bearer '+'c'.repeat(64)]) {
    const r=probe({token});assert.ok(r.error);assert.equal(r.made,0);assert.equal(r.calls.length,0);
  }
});
test('main emits only sanitized JSON on success and fixed stderr on any failure, with bounded deadline',()=>{
  const good=probe({main:true});assert.equal(good.code,0);assert.equal(good.err,'');assert.deepEqual(good.alarms,[15,0]);
  assert.deepEqual(JSON.parse(good.out),probe().result);
  for(const change of [{status:500},{body:'RAW_BODY_OR_HEADER_MUST_NEVER_APPEAR'},{networkError:true}]) {
    const bad=probe({main:true,...change});assert.equal(bad.code,1);assert.equal(bad.out,'');assert.equal(bad.err,'Deployment status check failed\n');assert.deepEqual(bad.alarms,[15,0]);
  }
});
