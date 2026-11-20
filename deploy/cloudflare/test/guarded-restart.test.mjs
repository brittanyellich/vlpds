import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';

const workflow=readFileSync(new URL('../../../.github/workflows/cloudflare-restart-qualified.yml',import.meta.url),'utf8');
const source=workflow.split('# BEGIN_GUARDED_RESTART\n')[1].split('# END_GUARDED_RESTART')[0].split('\n').map(line=>{
  if(!line.trim())return '';assert.ok(line.startsWith(' '.repeat(10)));return line.slice(10);
}).join('\n');
const harness=String.raw`
import contextlib, io, json, sys, types
p=json.load(sys.stdin);n={'__name__':'guarded_restart_test'};exec(p['source'],n)
env={'VLPDS_DEPLOY_TOKEN':'c'*64,'CLOUDFLARE_API_TOKEN':'t'*40,'CLOUDFLARE_ACCOUNT_ID':'a'*32}
expected='registry.cloudflare.com/'+env['CLOUDFLARE_ACCOUNT_ID']+'/vlpds@sha256:'+n['DIGEST']
old='registry.cloudflare.com/'+env['CLOUDFLARE_ACCOUNT_ID']+'/crate-pds-pds-pds@sha256:'+'f'*64
counts={'post':0,'status':0,'cold':0};calls=[];now=[0]
case=p.get('case','normal')
def payload(value):return json.dumps(value).encode()
def wire(method,host,path,headers,limit,prefix,remaining):
    assert remaining>0
    calls.append([method,host,path])
    if host==n['CF']:
        assert method=='GET' and headers['Authorization']=='Bearer '+env['CLOUDFLARE_API_TOKEN']
        if path.endswith('/deployments'):
            versions=[{'version_id':n['WORKER'],'percentage':100}]
            if case=='traffic':versions.append({'version_id':'other','percentage':1})
            return 200,'application/json',payload({'success':True,'result':{'deployments':[{'versions':versions}]}})
        assert path.endswith('/versions/'+n['WORKER'])
        texts={'AGENT_A2A_ENABLED':'false','AGENT_A2A_RUNTIME':'native-profile-v1','PUBLIC_HOST':n['PUBLIC'],'ADMIN_HOST':n['ADMIN'],'ENABLED':'true'}
        bindings=[{'name':key,'type':kind,**({'text':texts.get(key,'fixture')} if kind=='plain_text' else {})} for key,kind in n['EXPECTED_BINDINGS'].items()]
        if case=='enabled' or (case=='post-enabled' and counts['post']):
            next(row for row in bindings if row['name']=='AGENT_A2A_ENABLED')['text']='true'
        if case=='credential':bindings.append({'name':'AGENT_A2A_KODY_TOKEN','type':'secret_text'})
        if case=='alternate-credential':bindings.append({'name':'A2A_TOKEN','type':'secret_text'})
        if case=='binding-type':bindings[0]['type']='secret_text'
        return 200,'application/json',payload({'success':True,'result':{'id':n['WORKER'],'resources':{'bindings':bindings}}})
    if host==n['PUBLIC']:
        assert method=='GET' and 'Authorization' not in headers
        if path=='/account/spaces' and ((case=='cold' and counts['post']) or (case=='already-cold' and counts['status']>=2)) and counts['cold']<2:
            counts['cold']+=1;return 503,'text/plain',b'Pending'
        if path=='/account/spaces' and case in ['extra-script','inline-script','single-quote-script']:
            extra={'extra-script':'<script src="https://example.invalid/x.js"></script>','inline-script':'<script>alert(1)</script>','single-quote-script':"<script src='/extra.js'></script>"}[case]
            return 200,'text/html',('<script src="'+n['ASSET']+'"></script>'+extra).encode()
        if path=='/account/spaces':return 200,'text/html',('<script src="'+(n['ASSET'] if case!='ui' and not (case=='post-ui' and counts['post']) else '/assets/index-WRONG.js')+'"></script>').encode()
        if path==n['ASSET']:
            assert prefix and limit==1
            return 200,'text/javascript',b'x'
        if path==n['CARD']:return (200 if case=='card' else 404),'text/plain',b'Not found'
        assert path=='/xrpc/_health'
        if case=='stale':now[0]+=31
        return (503 if case=='health' else 200),'application/json',payload({'version':'fixture'})
    assert host==n['ADMIN'] and headers['Authorization']=='Bearer '+env['VLPDS_DEPLOY_TOKEN']
    if method=='GET':
        assert path=='/_deploy/status';counts['status']+=1
        desired=expected
        if case=='desired' or (case=='fresh-drift' and counts['status']==2) or (case=='post-drift' and counts['post']):desired=expected[:-1]+'0'
        current=expected if case in ['already','already-cold'] or (counts['post'] and case!='pending') else old
        if case=='other-image' and counts['post']:current=old.replace('f'*64,'e'*64)
        return 200,'application/json',payload({'desired':desired,'current':current,'running':case!='stopped'})
    assert method=='POST' and path=='/_deploy/restart' and headers['X-Deploy-Image']==expected
    counts['post']+=1;assert counts['post']==1
    if case=='timeout':raise TimeoutError('RAW_HEADER_OR_SECRET_MUST_NOT_APPEAR')
    if case=='refused':return 409,'text/plain',b'RAW_HEADER_OR_SECRET_MUST_NOT_APPEAR'
    return 202,'application/json',payload({'desired':expected if case!='ack' else old,'starting':True,'restarted':case!='not-restarted'})
def clock():return now[0]
def nap(seconds):now[0]+=seconds
original=n['Operator']
n['Operator']=lambda values,emit:original(values,wire=wire,clock=clock,nap=nap,emit=emit)
n['os']=types.SimpleNamespace(environ=env if case!='missing' else {})
n['signal']=types.SimpleNamespace(SIGALRM=14,ITIMER_REAL=0,signal=lambda *_:None,setitimer=lambda *_:None)
stdout,stderr=io.StringIO(),io.StringIO()
with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):code=n['main']()
print(json.dumps({'code':code,'records':[json.loads(line) for line in stdout.getvalue().splitlines()],'stderr':stderr.getvalue(),'counts':counts,'calls':calls}))
`;
function probe(caseName){
  const r=spawnSync('python3',['-c',harness],{input:JSON.stringify({source,case:caseName}),encoding:'utf8',timeout:5000});
  assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);
}
test('manual main-only workflow has no build/deploy/actions/inputs and reuses existing guarded operator path',()=>{
  assert.match(workflow,/permissions: \{\}/);assert.match(workflow,/workflow_dispatch:/);assert.match(workflow,/if: github.ref == 'refs\/heads\/main'/);
  assert.match(workflow,/group: crate-pds-cloudflare-production/);assert.match(workflow,/cancel-in-progress: false/);
  assert.ok(!/\buses:|inputs:|wrangler |docker |workflow_call:/.test(workflow));
  assert.equal((workflow.match(/\$\{\{ secrets\.[A-Z_]+ \}\}/g)??[]).length,3);
});
test('already-running exact image is verified with zero POSTs',()=>{
  const r=probe('already');assert.equal(r.code,0);assert.equal(r.counts.post,0);assert.equal(r.records.length,1);
  assert.equal(r.records[0].result,'already-running');assert.equal(r.records[0].restartAttempted,false);assert.equal(r.records[0].running,true);
});
test('normal path proves OFF scope, fresh desired and baseline before exactly one guarded POST',()=>{
  const r=probe('normal');assert.equal(r.code,0);assert.equal(r.counts.post,1);assert.equal(r.records.length,2);
  const post=r.calls.findIndex(([method])=>method==='POST');assert.ok(post>0);
  assert.ok(r.calls.slice(0,post).some(([,host,path])=>host==='api.cloudflare.com'&&path.endsWith('/versions/7572d63f-a93e-4bb3-876a-bba6348cba7e')));
  assert.deepEqual(r.calls[post-1],['GET','admin.crate.social','/_deploy/status']);
  const final=r.records.at(-1);assert.equal(final.result,'verified');assert.equal(final.desired,final.current);
  assert.equal(final.offConfigVerified,true);assert.equal(final.healthUiAndCard404Verified,true);assert.ok(final.current.includes('<account>'));
  assert.ok(!JSON.stringify(r.records).includes('a'.repeat(32)));
});
test('mismatched desired, changed scope/traffic, new secrets, stale or unhealthy baseline refuse before POST',()=>{
  for(const name of ['desired','fresh-drift','enabled','traffic','credential','alternate-credential','binding-type','stale','health','ui','extra-script','inline-script','single-quote-script','card','stopped','missing']){
    const r=probe(name);assert.equal(r.code,1,name);assert.equal(r.counts.post,0,name);assert.equal(r.records.at(-1).restartAttempted,false,name);
  }
});
test('refusal, ambiguous POST timeout, wrong ACK, drift and verification timeout never cause another POST',()=>{
  for(const name of ['refused','timeout','ack','not-restarted','post-drift','pending','post-enabled','post-ui','other-image']){
    const r=probe(name);assert.equal(r.code,1,name);assert.equal(r.counts.post,1,name);assert.equal(r.records.at(-1).restartAttempted,true,name);
    assert.equal(r.stderr,'Guarded restart failed; no retry performed\n');
    assert.ok(!JSON.stringify(r).includes('RAW_HEADER_OR_SECRET_MUST_NOT_APPEAR'));
  }
});
test('temporary public boot failures poll reads only; the POST is not retried',()=>{
  const r=probe('cold');assert.equal(r.code,0);assert.equal(r.counts.post,1);assert.equal(r.counts.cold,2);assert.equal(r.records.at(-1).result,'verified');
  const already=probe('already-cold');assert.equal(already.code,0);assert.equal(already.counts.post,0);assert.equal(already.counts.cold,2);assert.equal(already.records.at(-1).result,'already-running');
});
test('transport closes and bounds reads/deadlines using verified TLS with no redirect/retry',()=>{
  const script=String.raw`
import json,ssl,sys,types
p=json.load(sys.stdin);n={'__name__':'transport_test'};exec(p['source'],n);seen=[];closed=[];timers=[]
class Response:
    status=200
    def getheader(self,k,default=None):return {'Content-Type':'application/json'}.get(k,default)
    def read(self,limit):assert limit==4097;return b'{}'
class Connection:
    def __init__(self,host,port,timeout,context):assert host=='admin.crate.social' and port==443 and timeout==10 and context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED
    def request(self,method,path,body,headers):seen.append([method,path]);assert method=='GET' and path=='/_deploy/status'
    def getresponse(self):return Response()
    def close(self):closed.append(True)
n['http'].client.HTTPSConnection=Connection;n['signal']=types.SimpleNamespace(ITIMER_REAL=0,setitimer=lambda _,value:timers.append(value))
assert n['exchange']('GET','admin.crate.social','/_deploy/status',{},4096,False,300)==(200,'application/json',b'{}')
assert seen==[['GET','/_deploy/status']] and closed==[True] and timers==[15,0]
print('PASS')
`;
  const r=spawnSync('python3',['-c',script],{input:JSON.stringify({source}),encoding:'utf8',timeout:5000});assert.equal(r.status,0,r.stderr);assert.equal(r.stdout.trim(),'PASS');
});
