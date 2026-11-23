"""Inert integration worker: synthetic trust, MockTransport, network denied."""
import asyncio
import base64
import hashlib
import io
import json
import os
import socket
import sys
import termios
import select
import signal
import zipfile
from pathlib import Path

# Deny native networking before importing the consumer. No live transport exists.
network_denied = 0
def deny_connect(*args, **kwargs):
    global network_denied
    network_denied += 1
    raise RuntimeError("Rehearsal networking denied")
socket.socket.connect = deny_connect
socket.socket.connect_ex = deny_connect
socket.getaddrinfo = deny_connect
socket.socket.sendto = deny_connect
socket.create_connection = deny_connect

source, bundle_path, output = map(Path, sys.argv[1:4])
bundle = json.loads(bundle_path.read_text())
if bundle.get('rehearsalOnly') is not True or not sys.stdin.isatty():
    raise SystemExit(2)
sys.path[:0] = [str(source), str(source / 'tests')]
import httpx
import pytest
from portable_agent import otto_acceptance_operator as operator
from portable_agent.otto_acceptance import AGENT, PRINCIPAL
from portable_agent.service_auth_check import ISS
from test_otto_acceptance import synthetic_card

clock = bundle['now']
counts = {'prompt': 0, 'mockLogin': 0, 'mockRequests': 0}
phase = 'readiness'
private_input = {'echoDisabled': False, 'echoRestored': False, 'inputMatched': False, 'timedOut': False, 'stopped': False}
class GitHub:
    async def json(self, path):
        if path.endswith('/jobs?per_page=100'): return bundle['jobs']
        if path.endswith('/artifacts?per_page=100'): return bundle['artifacts']
        return bundle['run']
    async def bytes(self, path): return base64.b64decode(bundle['zip'])

def prompt(_):
    global clock, phase
    phase = 'unlock'; counts['prompt'] += 1
    clock += bundle['unlockSeconds']
    if bundle['unlockSeconds'] > 60: raise TimeoutError('Synthetic unlock timeout')
    if bundle.get('entry') == 'operator-cli-fixture':
        fd = sys.stdin.fileno()
        original = termios.tcgetattr(fd)
        changed = original.copy()
        changed[3] &= ~(termios.ECHO | termios.ECHONL)
        previous_signal = signal.getsignal(signal.SIGTERM)
        def stop(*_):
            private_input['stopped'] = True
            raise InterruptedError('Synthetic fixture stopped')
        signal.signal(signal.SIGTERM, stop)
        try:
            termios.tcsetattr(fd, termios.TCSAFLUSH, changed)
            private_input['echoDisabled'] = not bool(termios.tcgetattr(fd)[3] & (termios.ECHO | termios.ECHONL))
            ready = output.parent / 'operator-ready.json'
            mark = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(mark, 'w') as stream:
                json.dump({'echoDisabled': private_input['echoDisabled'], 'pid': os.getpid()}, stream)
            # Fixed synthetic label and input only; neither is captured.
            sys.stderr.write('EXP-710 SYNTHETIC EXECUTOR INPUT (hidden): ')
            sys.stderr.flush()
            if not select.select([fd], [], [], bundle['privateInputSeconds'])[0]:
                private_input['timedOut'] = True
                raise TimeoutError('Synthetic private input timeout')
            value = os.read(fd, 256)
            private_input['inputMatched'] = value.rstrip(b'\r\n') == b'SYNTHETIC_ONLY'
            value = None
            if not private_input['inputMatched']:
                raise ValueError('Synthetic input refused')
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, original)
            private_input['echoRestored'] = termios.tcgetattr(fd) == original
            signal.signal(signal.SIGTERM, previous_signal)
    return 'SYNTHETIC_ONLY_PASSWORD'

async def main():
    global phase, clock
    with pytest.MonkeyPatch.context() as patch:
        card, doc = synthetic_card(patch)  # Real ES256 verification, synthetic authority.
        if bundle['case'] == 'invalid-signature': card['signatures'][0]['signature'] = 'invalid'
        async def fresh(*_): return 'SYNTHETIC_ONLY_JWT', {}
        patch.setattr(operator, 'request_verified_service_token', fresh)
        def handler(request):
            global clock, phase
            if request.url.host == 'plc.directory':
                return httpx.Response(200, json=doc if request.url.path == '/' + AGENT else {'id': ISS, 'service': [{'id': ISS+'#atproto_pds', 'type': 'AtprotoPersonalDataServer', 'serviceEndpoint': operator.OTTO_PDS_ORIGIN}]})
            if request.url.path.endswith('createSession'):
                counts['mockLogin'] += 1
                return httpx.Response(200, json={'did': ISS, 'accessJwt': 'SYNTHETIC_ONLY_ACCESS'})
            if request.method == 'GET':
                return httpx.Response(200, json={} if request.url.path in ('/xrpc/_health', '/account/spaces') else card)
            phase = 'request'; counts['mockRequests'] += 1
            clock += bundle['requestSeconds']
            if bundle['requestSeconds'] > 10: raise TimeoutError('Synthetic request timeout')
            body = json.loads(request.content)
            return httpx.Response(200, json={'jsonrpc':'2.0','id':body['id'],'result':{'message':{'role':'ROLE_AGENT','messageId':'stable','contextId':'stable','metadata':{'identityEvaluation':{'atUnix':100,'commitCid':'synthetic-commit','recordCid':'synthetic-record'}},'parts':[{'data':{'agentDid':AGENT,'principalDid':PRINCIPAL,'status':'verified'}}]}}})
        receipt = output.parent / 'synthetic-acceptance.json'
        if bundle.get('entry') == 'operator-cli-fixture':
            args = bundle['launcherArgs']
            if len(args) != 5 or args[:2] != ['-m', 'portable_agent.run_otto_acceptance'] or args[2] != str(bundle['run']['id']) or args[3] != bundle['run']['head_sha'] or Path(args[4]).parent != output.parent:
                raise ValueError('Fixture launch plan refused')
            receipt = Path(args[4])
        try:
            if bundle.get('entry') == 'operator-cli-fixture':
                from portable_agent import run_otto_acceptance as cli
                original_client = httpx.AsyncClient
                patch.setattr(cli, 'GitHub', GitHub)
                patch.setattr(cli.httpx, 'AsyncClient', lambda **_: original_client(transport=httpx.MockTransport(handler)))
                patch.setattr(cli.time, 'time', lambda: clock)
                async def private_runner(*args):
                    return await operator.run_private_acceptance(*args, prompt=prompt, clock=lambda: clock)
                patch.setattr(cli, 'run_private_acceptance', private_runner)
                result = await cli.main(int(args[2]), args[3], receipt)
            else:
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    result = await operator.run_private_acceptance(client, GitHub(), bundle['run']['id'], bundle['run']['head_sha'], int(clock), receipt, prompt=prompt, clock=lambda: clock)
            accepted = result == {'receiptWritten': True, 'result': 'PASS'}
        except Exception:
            accepted = False
        # A direct native connection is denied before any network operation.
        try:
            with socket.socket() as probe: probe.connect(('127.0.0.1', 9))
        except RuntimeError: pass
        else: raise AssertionError('Network guard did not fail closed')
        result = {'rehearsal':True,'tty':True,'liveRequests':0,'realPrompt':False,'acceptedSynthetic':accepted,'counts':counts,'lastPhase':phase,'networkProbeDenied':network_denied == 1,'proofAgeSeconds':clock-bundle['checkedAt'],'remainingLeaseSeconds':bundle['deadline']-clock,'cliMainExercised':bundle.get('entry')=='operator-cli-fixture','privateInput':private_input}
        fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream: json.dump(result, stream)
asyncio.run(main())
