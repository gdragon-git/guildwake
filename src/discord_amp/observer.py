"""Linux-only read-only acquisition. No subprocess, AMP session or Docker API."""
from .config import current
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from .guard import assess, Verdict
from .observer_errors import details as failure_details



MAX_SCAN_PAIRS = 2
OBSERVATION_BUDGET = 1.0

class ProcessTurnover(FileNotFoundError):
    """A per-PID read vanished. The incomplete scan is never permissive."""


def process_read(read):
    # Only per-PID dynamic reads use this boundary. Missing storage, inventory,
    # protected maintenance files or container mapping stays acquisition_failed.
    try:
        return read()
    except FileNotFoundError as exc:
        raise ProcessTurnover(exc.errno or 2, 'process_turnover') from None


def turnover_only(first, second):
    """A conservative retry filter, never a permissive guard verdict."""
    if not any(s['errors'] == ['process_turnover'] for s in (first, second)):
        return False
    for snap in (first, second):
        if snap['errors'] not in ([], ['process_turnover']):
            return False
        for row in snap['rows'].values():
            # Do not let a torn scan erase observed maintenance, another game,
            # unclassified AMP work or the selected running application.
            if (row.get('maintenance') or (row.get('management') is not True
                    and not (row.get('instances') == ((current().selected),)
                             and row.get('application_activity') is False))):
                return False
    return True


class Collector:
    def __init__(self, amp_uid, proc=Path('/proc'), cgroup=Path('/sys/fs/cgroup'), error_reporter=None, monotonic=time.monotonic):
        self.amp_uid, self.proc, self.cgroup = amp_uid, proc, cgroup
        self.now = monotonic
        self.error_reporter = error_reporter
        self.last_failure = None
        self.reporting_failed = False

    @staticmethod
    def inode(path):
        st = path.stat()
        return st.st_dev, st.st_ino

    def inventory(self):
        mount = Path(current().storage_mount)
        if not mount.is_mount() or mount.stat().st_dev != Path('/dev/disk/by-uuid/' + (current().storage_uuid)).stat().st_rdev:
            raise ValueError('storage')
        path = Path(current().inventory_path)
        before = path.stat()
        with path.open('rb') as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('inventory')
        rows = json.loads(raw)
        expected = sorted((name, *data) for name, data in (current().instances).items())
        selected = [(r['InstanceName'], r['InstanceID'], r['Path']) for r in rows]
        after = path.stat()
        if (sorted(selected) != expected or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError('inventory')
        roots = {name: self.inode(Path(data[1])) for name, data in (current().instances).items()}
        return hashlib.sha256(json.dumps([expected, sorted(roots.items())]).encode()).hexdigest(), roots

    def membership(self):
        groups = {}
        walked = 0
        def fail(_):
            raise ValueError('cgroup')
        for directory, _, files in os.walk(self.cgroup, onerror=fail):
            walked += 1
            if walked > 8192:
                raise ValueError('cgroup_limit')
            # Include descendants of Docker scopes, not just their root PIDs.
            parts = Path(directory).relative_to(self.cgroup).parts
            scopes = [p for p in parts if p.startswith('docker-') and p.endswith('.scope')]
            if scopes:
                scope = scopes[0]
                group = groups.setdefault(scope, set())
                if 'cgroup.procs' in files:
                    group.update(int(p) for p in (Path(directory) / 'cgroup.procs').read_text().split())
        if sum(len(v) for v in groups.values()) > 32768:
            raise ValueError('process_limit')
        return groups

    @staticmethod
    def stat_fields(path):
        value = path.read_text()
        close = value.rfind(')')
        return value[value.find('(') + 1:close], value[close + 2:].split()

    @staticmethod
    def protected_binary(path):
        st = Path(path).stat()
        return st.st_uid == 0 and not st.st_mode & 0o022

    @staticmethod
    def protected_identity(path):
        value = Path(path).stat()
        if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise ValueError('unprotected_maintenance_identity')
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_mode)

    def maintenance_identity(self, proc, uid, exe, comm, roots, fields, cg):
        # This identifies blocking maintenance, never a management exemption.
        # No command line, environment, unit contents or new privilege is needed.
        if (uid != self.amp_uid or exe != (current().maintenance_exe) or comm != 'ampinstmgr' or roots
                or fields[1] != '1' or cg != '0::/system.slice/amptasks.service\n'):
            return ''
        try:
            binary = self.protected_identity((current().maintenance_exe))
            unit = self.protected_identity((current().maintenance_unit))
            parent_binary = self.protected_identity((current().systemd_exe))
            parent = self.proc / '1'
            parent_comm, parent_fields = self.stat_fields(parent / 'stat')
            if (Path((current().maintenance_unit)).is_symlink()
                    or os.path.realpath((current().maintenance_alias)) != (current().maintenance_exe)
                    or self.inode(proc / 'exe') != binary[:2]
                    or parent.stat().st_uid != 0 or parent_comm != 'systemd'
                    or os.readlink(parent / 'exe') != (current().systemd_exe)
                    or self.inode(parent / 'exe') != parent_binary[:2]
                    or int(parent_fields[19]) <= 0):
                return ''
            # Pin metadata across acquisition and include it in both-scan signatures.
            parent_after, after_fields = self.stat_fields(parent / 'stat')
            if (self.protected_identity((current().maintenance_exe)) != binary
                    or self.protected_identity((current().maintenance_unit)) != unit
                    or self.protected_identity((current().systemd_exe)) != parent_binary
                    or parent_after != parent_comm or after_fields[19] != parent_fields[19]
                    or parent.stat().st_uid != 0 or os.readlink(parent / 'exe') != (current().systemd_exe)):
                return ''
            return hashlib.sha256(json.dumps([binary, unit, parent_binary, parent_fields[19]]).encode()).hexdigest()
        except (OSError, ValueError, IndexError):
            return ''

    def management(self, proc, uid, exe, comm, roots, fields, cg):
        if uid != self.amp_uid:
            return False
        if exe == (current().systemd_exe) and comm == 'systemd':
            return self.protected_binary(exe)
        if exe == (current().systemd_exe + '-executor') and comm == '(sd-pam)':
            parent = self.proc / fields[1]
            parent_comm, _ = self.stat_fields(parent / 'stat')
            return (self.protected_binary(exe) and parent.stat().st_uid == uid
                    and parent_comm == 'systemd' and os.readlink(parent / 'exe') == (current().systemd_exe)
                    and (parent / 'cgroup').read_text() == cg)
        if roots == (current().management,):
            return (exe == (current().instances)[current().management][1] + ('/' + current().amp_binary)
                    or exe == '/usr/bin/tmux' and self.protected_binary(exe))
        return False

    def report_failure(self, detail):
        self.last_failure = detail.copy()
        if self.error_reporter is not None:
            try:
                self.reporting_failed = self.error_reporter(detail.copy()) is not True
            except Exception:
                self.reporting_failed = True

    def scan(self):
        start = self.now()
        snap = dict(start=start, end=start, boot='', inventory_ok=False, errors=[], rows={},
                    relevant_pids=[], container_pids=[], unmapped_containers=True, inventory='')
        stage, pid, ticks, process_state = 'boot', None, None, None
        try:
            snap['boot'] = (self.proc / 'sys/kernel/random/boot_id').read_text().strip()
            stage = 'inventory'
            fingerprint, root_ids = self.inventory()
            snap.update(inventory_ok=True, inventory=fingerprint)
            stage = 'membership'
            members = self.membership()
            stage = 'membership_check'
            if any(not pids for pids in members.values()):
                raise ValueError('empty_container')
            container_pids = set()
            for group in members.values():
                if container_pids & group:
                    raise ValueError('duplicate_membership')
                container_pids.update(group)
            stage = 'process_list'
            pids = sorted(int(p.name) for p in self.proc.iterdir() if p.name.isdecimal())
            if len(pids) > 32768:
                raise ValueError('process_limit')
            mapped = set()
            for pid in pids:
                ticks, process_state = None, None
                stage = 'process_owner'
                proc = self.proc / str(pid)
                uid = process_read(lambda: proc.stat().st_uid)
                stage = 'process_stat'
                comm, fields = process_read(lambda: self.stat_fields(proc / 'stat'))
                stage = 'process_state'
                process_state = fields[0]
                ticks = int(fields[19])
                if int(fields[6]) & 0x200000:  # PF_KTHREAD; no userspace executable
                    continue
                if fields[0] in {'Z', 'X', 'x'}:
                    raise ValueError('exiting_process')
                stage = 'process_exe'
                exe = process_read(lambda: os.readlink(proc / 'exe'))
                stage = 'process_cwd'
                cwd = process_read(lambda: os.readlink(proc / 'cwd'))
                stage = 'process_cgroup'
                cg = process_read(lambda: (proc / 'cgroup').read_text())
                if not cg.startswith('0::') or exe.endswith(' (deleted)'):
                    raise ValueError('unreadable_identity')
                stage = 'process_roots'
                roots = {name for name, (_, path) in (current().instances).items()
                         if any(value == path or value.startswith(path + '/') for value in (exe, cwd))}
                container = None
                stage = 'process_container'
                if pid in container_pids:
                    ident = self.inode(proc / 'root/AMP')
                    names = [n for n, value in root_ids.items() if ident == value]
                    if len(names) != 1:
                        raise ValueError('unmapped_container')
                    container = names[0]
                    roots.add(container)
                    scopes = [name for name, group in members.items() if pid in group]
                    if len(scopes) != 1 or ('/' + scopes[0]) not in cg:
                        raise ValueError('membership_disagreement')
                    mapped.add(pid)
                roots = tuple(sorted(roots))
                stage = 'process_maintenance'
                maintenance = self.maintenance_identity(proc, uid, exe, comm, roots, fields, cg) if container is None else ''
                stage = 'process_recheck'
                _, after = process_read(lambda: self.stat_fields(proc / 'stat'))
                if (int(fields[19]) != int(after[19]) or process_read(lambda: proc.stat().st_uid) != uid
                        or process_read(lambda: os.readlink(proc / 'exe')) != exe or process_read(lambda: os.readlink(proc / 'cwd')) != cwd
                        or process_read(lambda: (proc / 'cgroup').read_text()) != cg):
                    raise ValueError('identity_changed')
                stage = 'process_classify'
                if uid != self.amp_uid and not roots and container is None:
                    continue
                # Raw paths/cgroups only stay inside this privileged process.
                fp = hashlib.sha256(json.dumps([uid, exe, cwd, cg, maintenance]).encode()).hexdigest()
                is_controller = (exe == ('/AMP/' + current().amp_binary) or exe == (current().instances)[(current().selected)][1] + ('/' + current().amp_binary))
                is_init = container == (current().selected) and Path(exe).name == 'tini'
                snap['rows'][pid] = dict(start_ticks=int(fields[19]), instances=roots, stable=True,
                    container=container, fingerprint=fp,
                    management=self.management(proc, uid, exe, comm, roots, fields, cg),
                    maintenance=bool(maintenance),
                    application_activity=not (is_controller or is_init))
            stage, pid, ticks, process_state = 'membership_recheck', None, None, None
            current_members = self.membership()
            if members != current_members:
                raise ValueError('source_changed')
            stage = 'inventory_recheck'
            if fingerprint != self.inventory()[0]:
                raise ValueError('source_changed')
            snap.update(relevant_pids=tuple(snap['rows']), container_pids=tuple(container_pids),
                        unmapped_containers=mapped != container_pids)
        except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError) as exc:
            snap['errors'] = ['process_turnover'] if isinstance(exc, ProcessTurnover) else ['acquisition_failed']
            snap['failure_detail'] = failure_details(exc, stage, pid, ticks, process_state)
            self.report_failure(snap['failure_detail'])
        snap['end'] = self.now()
        return snap

    def verdict(self):
        began = self.now()
        for attempt in range(MAX_SCAN_PAIRS):
            first, second = self.scan(), self.scan()
            try:
                boot = (self.proc / 'sys/kernel/random/boot_id').read_text().strip()
            except OSError as exc:
                self.report_failure(failure_details(exc, 'closing_boot'))
                return Verdict()
            now = self.now()
            if now - began > OBSERVATION_BUDGET:
                return Verdict(reason='stale_observation')
            value = assess(first, second, now, boot)
            # A fresh *complete pair* can replace a torn acquisition before any
            # mutation intent. Never ignore a missing PID, merge scans, reuse a
            # permissive cache or retry busy/unclassified/static failures.
            if value.state != 'unknown' or not turnover_only(first, second):
                return value
        return value
