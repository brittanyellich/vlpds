"""Synthetic input/receipt stand-in for qualifying the shared Terminal executor."""
import getpass
import errno
import socket
import json
import os
from pathlib import Path
import sys

assert len(sys.argv) == 4 and sys.stdin.isatty()
with socket.socket() as probe:
    try:
        probe.connect(('127.0.0.1', 9))
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES)
    else:
        raise AssertionError('OS network isolation required')
value = getpass.getpass('EXP-710 SYNTHETIC PRIVATE INPUT: ')
matched = value == 'SYNTHETIC_ONLY'
value = None
if not matched:
    raise SystemExit(1)
result = {'result': 'PASS', 'cardSignatureValid': True,
          'caller': 'did:plc:vsgwub3c3pupqt3yhxfmecma',
          'audience': 'did:web:pds.crate.social',
          'lxm': 'chat.atagents.agent.contact', 'status': 'verified', 'stableRetry': True}
fd = os.open(Path(sys.argv[3]), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump(result, stream)
