"""Synthetic input only; never records input or prompt contents."""
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import sys
import termios
import time

root = Path(sys.argv[1])
seconds = float(sys.argv[2])
if not 0.1 <= seconds <= 30 or not sys.stdin.isatty(): raise SystemExit(2)
fd = sys.stdin.fileno()
original = termios.tcgetattr(fd)
changed = original.copy()
changed[3] &= ~(termios.ECHO | termios.ECHONL)
result = {'synthetic': True, 'tty': True, 'inputMatched': False, 'timedOut': False, 'echoDisabled': False, 'echoRestored': False, 'networkDenied': False}
def save(name, value):
    target = root / name
    out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(out, 'w') as stream: json.dump(value, stream)
def stop(*_): raise InterruptedError('Synthetic fixture interrupted')
signal.signal(signal.SIGTERM, stop)
try:
    with socket.socket() as probe:
        try: probe.connect(('127.0.0.1', 9))
        except OSError as error: result['networkDenied'] = error.errno in (errno.EPERM, errno.EACCES)
    if not result['networkDenied']: raise RuntimeError('OS network isolation unavailable')
    termios.tcsetattr(fd, termios.TCSAFLUSH, changed)
    result['echoDisabled'] = not bool(termios.tcgetattr(fd)[3] & (termios.ECHO | termios.ECHONL))
    # The only presentation text is a fixed noncredential label; never captured.
    sys.stderr.write('EXP-710 SYNTHETIC INPUT CHECK (hidden input): ')
    sys.stderr.flush()
    save('surface-ready.json', {'ready': True, 'echoDisabled': result['echoDisabled'], 'deadline': time.time() + seconds})
    if select.select([fd], [], [], seconds)[0]:
        value = os.read(fd, 256)
        result['inputMatched'] = value.rstrip(b'\r\n') == b'SYNTHETIC_ONLY'
        value = None
    else:
        result['timedOut'] = True
except InterruptedError:
    result['interrupted'] = True
finally:
    termios.tcsetattr(fd, termios.TCSANOW, original)
    result['echoRestored'] = termios.tcgetattr(fd) == original
    save('surface-result.json', result)
