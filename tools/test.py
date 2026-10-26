"""Run offline/synthetic checks; no live game or Discord login is permitted."""
import json
from pathlib import Path
import socket
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]


def guard(event, args):
    if event in {'socket.connect', 'socket.sendto', 'socket.bind'}:
        address = args[-1]
        if isinstance(address, tuple) and address[0] not in {'127.0.0.1', '::1'}:
            raise RuntimeError('test_nonloopback_network_forbidden')


sys.addaudithook(guard)
suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
result = unittest.TextTestRunner(verbosity=1).run(suite)
print(json.dumps({'tests_run': result.testsRun, 'skipped': len(result.skipped),
                  'failures': len(result.failures), 'errors': len(result.errors),
                  'passed': result.wasSuccessful(), 'proof': 'local portable/synthetic; Linux cases skip on Windows',
                  'independent_installation_qualified': False}))
raise SystemExit(0 if result.wasSuccessful() else 1)
