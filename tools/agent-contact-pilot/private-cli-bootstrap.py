"""Private process supervision only; never reads, records or transforms input."""
import getpass
import json
import os
from pathlib import Path
import runpy
import signal
import sys
import termios

config = json.loads(Path(sys.argv[1]).read_text())
root = Path(config['root'])
def mark(name, data):
    temp = root / (name + '.writing')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
    os.replace(temp, root / name)
def stop(*_):
    raise InterruptedError('Private execution stopped')
signal.signal(signal.SIGTERM, stop)
# Isolate only this owned Terminal process and its future descendants.
try:
    if os.getpgrp() != os.getpid():
        previous_ttou = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        try:
            os.setpgid(0, 0)
            os.tcsetpgrp(0, os.getpgrp())
        finally:
            signal.signal(signal.SIGTTOU, previous_ttou)
except OSError:
    mark('process.json', {'pid': os.getpid(), 'pgid': os.getpgrp()})
    mark('done.json', {'exitCode': 1})
    raise SystemExit(1)
mark('process.json', {'pid': os.getpid(), 'pgid': os.getpgrp()})
original_getpass = getpass.getpass
original_set = termios.tcsetattr
in_prompt = False
ready = False
def observe_mode(fd, when, attrs):
    global ready
    original_set(fd, when, attrs)
    if in_prompt and not ready and not (termios.tcgetattr(fd)[3] & termios.ECHO):
        ready = True
        mark('ready.json', {'phase': 'private-unlock', 'echoDisabled': True})
def private_prompt(*args, **kwargs):
    global in_prompt
    before = termios.tcgetattr(0)
    in_prompt = True
    try:
        return original_getpass(*args, **kwargs)
    finally:
        in_prompt = False
        mark('unlocked.json', {'echoRestored': termios.tcgetattr(0) == before})
termios.tcsetattr = observe_mode
getpass.getpass = private_prompt
sys.path.insert(0, config['dependencies'])
sys.path.insert(0, config['source'])
sys.argv = ['portable_agent.run_otto_acceptance', *config['args']]
code = 1
try:
    runpy.run_module('portable_agent.run_otto_acceptance', run_name='__main__')
    code = 0
except SystemExit as error:
    code = error.code if type(error.code) is int else 1
except BaseException:
    code = 1
finally:
    mark('done.json', {'exitCode': code})
raise SystemExit(code)
