"""Bounded owner-local observer diagnostics; no raw exception text or command data."""
import json
import os
from pathlib import Path
import stat
import time

STAGES = frozenset(('boot', 'inventory', 'membership', 'membership_check', 'process_list',
                    'process_owner', 'process_stat', 'process_state', 'process_exe',
                    'process_cwd', 'process_cgroup', 'process_roots', 'process_container',
                    'process_maintenance', 'process_recheck', 'process_classify',
                    'membership_recheck', 'inventory_recheck', 'closing_boot', 'unknown'))
CODES = frozenset(('storage', 'inventory', 'cgroup', 'cgroup_limit', 'process_limit',
                   'empty_container', 'duplicate_membership', 'exiting_process',
                   'unreadable_identity', 'unmapped_container', 'membership_disagreement',
                   'identity_changed', 'source_changed', 'unprotected_maintenance_identity'))
TYPES = ('FileNotFoundError', 'ProcessLookupError', 'PermissionError', 'OSError',
         'ValueError', 'TypeError', 'KeyError', 'IndexError', 'RecursionError', 'unknown')
KEYS = frozenset(('stage', 'type', 'code', 'errno', 'pid', 'start_ticks', 'process_state'))
MAX_BYTES = 4096
NAME = 'last-acquisition-error.json'
PENDING = '.last-acquisition-error.pending'


def integer(value, lower, upper):
    return value if type(value) is int and lower <= value <= upper else None


def project(value):
    """A second whitelist at the persistence boundary; never forward extra keys."""
    value = value if type(value) is dict else {}
    return dict(stage=value.get('stage') if type(value.get('stage')) is str and value['stage'] in STAGES else 'unknown',
                type=value.get('type') if type(value.get('type')) is str and value['type'] in TYPES else 'unknown',
                code=value.get('code') if type(value.get('code')) is str and value['code'] in CODES else None,
                errno=integer(value.get('errno'), 1, 4095),
                pid=integer(value.get('pid'), 1, 2147483647),
                start_ticks=integer(value.get('start_ticks'), 1, 18446744073709551615),
                process_state=value.get('process_state') if value.get('process_state') in
                ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'x', 'I') else None)


def details(exc, stage, pid=None, start_ticks=None, process_state=None):
    kind = next((name for cls, name in ((FileNotFoundError, 'FileNotFoundError'),
                (ProcessLookupError, 'ProcessLookupError'), (PermissionError, 'PermissionError'),
                (OSError, 'OSError'), (ValueError, 'ValueError'), (TypeError, 'TypeError'),
                (KeyError, 'KeyError'), (IndexError, 'IndexError'), (RecursionError, 'RecursionError'))
                 if isinstance(exc, cls)), 'unknown')
    code = exc.args[0] if type(exc) is ValueError and len(exc.args) == 1 else None
    return project(dict(stage=stage, type=kind, code=code if type(code) is str else None,
                        errno=getattr(exc, 'errno', None), pid=pid,
                        start_ticks=start_ticks, process_state=process_state))


class ErrorRecord:
    """One atomic /run record, root-only mode0600. Never clears on successful scan.

    An occupied pending name, unsafe target or publication error refuses reporting;
    it never authorizes observation or deletes uncertain state. No socket or API.
    """
    def __init__(self, directory=Path('/run/discord-amp-observer')):
        self.directory = Path(directory)
        self.sequence = 0

    @staticmethod
    def regular(info):
        return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                0 <= info.st_size <= MAX_BYTES)

    def __call__(self, failure):
        directory = fd = None
        try:
            if os.geteuid() != 0:
                return False
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(directory)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
            try:
                existing = os.stat(NAME, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and not self.regular(existing):
                return False
            self.sequence += 1
            raw = (json.dumps({'schema': 1, 'sequence': self.sequence,
                              'observed_ns': time.time_ns(), 'failure': project(failure)},
                              sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')
            if len(raw) > MAX_BYTES:
                return False
            fd = os.open(PENDING, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                fd = None
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(PENDING, NAME, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            return True
        except (OSError, ValueError, TypeError):
            return False
        finally:
            if fd is not None:
                os.close(fd)
            if directory is not None:
                os.close(directory)
