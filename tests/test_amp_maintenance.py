import profile_fixture
"""Task identity, fail-closed reduction and end-to-end denial; no real AMP/WOL."""
import asyncio
from dataclasses import asdict, replace
from pathlib import Path
import os
import sys
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import importlib.util

from discord_amp import observer
from discord_amp.observer import Collector
from discord_amp.guard import assess, Verdict
from discord_amp.broker import Broker
from discord_amp.controller import Controller
from discord_amp.services import observer_call
from discord_amp.model import Fault
from profile_fixture import OWNER
from discord_amp.store import Store
from discord_amp.wire import serve_unix
from discord_amp.bot import MESSAGES
from test_core import snapshot, Backend, Clock, request


def task_row(**changes):
    return dict(start_ticks=42, instances=(), stable=True, container=None,
                fingerprint='protected-task', management=False, application_activity=True,
                maintenance=True, **changes)


class MaintenanceReductionTests(unittest.TestCase):
    def reduce(self, rows, second=None):
        return assess(snapshot(rows=rows), snapshot(100.02, rows if second is None else second), 100.04, 'boot')

    def test_known_task_is_covered_busy_never_clear(self):
        result = self.reduce({9: task_row()})
        self.assertEqual((result.state, result.reason, result.covered, result.selected_active),
                         ('busy', 'amp_maintenance', True, False))

    def test_task_and_selected_game_remain_busy(self):
        rows = snapshot()['rows']; rows[9] = task_row()
        result = self.reduce(rows)
        self.assertEqual((result.state, result.reason), ('busy', 'amp_maintenance'))
        self.assertTrue(result.selected_active)

    def test_unknown_cannot_be_hidden_by_known_task(self):
        row = task_row(); row['maintenance'] = False
        self.assertEqual(self.reduce({8: row, 9: task_row()}).state, 'unknown')

    def test_other_game_stays_busy_with_maintenance(self):
        row = task_row(); row.update(maintenance=False, instances=('ZomboidLAN01',))
        result = self.reduce({8: row, 9: task_row()})
        self.assertEqual((result.state, result.reason), ('busy', 'other_activity'))

    def test_forged_maintenance_shape_stays_unknown(self):
        for change in [dict(management=True), dict(instances=('Enshrouded01',)),
                       dict(container='Enshrouded01'), dict(application_activity=False), dict(maintenance='yes')]:
            row = task_row(); row.update(change)
            with self.subTest(change=change):
                self.assertEqual(self.reduce({9: row}).state, 'unknown')

    def test_task_disappearance_or_identity_change_stays_unknown(self):
        for after in [{}, {9: {**task_row(), 'fingerprint': 'changed'}},
                      {9: {**task_row(), 'start_ticks': 43}}, {9: {**task_row(), 'maintenance': False}}]:
            with self.subTest(after=after):
                self.assertEqual(self.reduce({9: task_row()}, after).state, 'unknown')

    def test_incomplete_or_stale_task_coverage_stays_unknown(self):
        rows = {9: task_row()}
        for change in [dict(errors=['acquisition_failed']), dict(unmapped_containers=True), dict(end=90)]:
            with self.subTest(change=change):
                result = assess({**snapshot(rows=rows), **change}, snapshot(100.02, rows), 100.04, 'boot')
                self.assertEqual(result.state, 'unknown')


class MaintenanceIdentityTests(unittest.TestCase):
    def test_wrong_name_uid_parent_path_cgroup_or_instance_does_not_identify(self):
        collector = Collector(1001)
        fields = ['S', '1'] + ['0'] * 20
        values = dict(proc=Path('/proc/42'), uid=1001, exe='/opt/cubecoders/amp/ampinstmgr',
                      comm='ampinstmgr', roots=(), fields=fields, cg='0::/system.slice/amptasks.service\n')
        for change in [dict(uid=0), dict(exe='/tmp/ampinstmgr'), dict(comm='renamed'),
                       dict(roots=('Enshrouded01',)), dict(fields=['S', '99'] + ['0'] * 20),
                       dict(cg='0::/user.slice/amptasks.service\n'),
                       dict(cg='0::/system.slice/amptasks.service/child\n'),
                       dict(cg='0::/system.slice/amptasks.service.evil\n')]:
            with self.subTest(change=change):
                self.assertEqual(collector.maintenance_identity(**{**values, **change}), '')


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Native root-owned Linux identity fixtures')
class NativeMaintenanceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='amp-task-identity-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary, self.systemd, self.unit = (self.root / n for n in ['ampinstmgr', 'systemd', 'amptasks.service'])
        for p in [self.binary, self.systemd, self.unit]:
            p.write_bytes(b'root-owned fixture'); p.chmod(0o755 if p != self.unit else 0o644)
        self.alias = self.root / 'alias'; self.alias.symlink_to(self.binary)
        self.proc = self.root / 'proc'; self.proc.mkdir()
        self.pid = self.proc / '42'; self.pid.mkdir(); os.chown(self.pid, 1001, -1)
        (self.pid / 'exe').symlink_to(self.binary)
        self.parent = self.proc / '1'; self.parent.mkdir()
        (self.parent / 'exe').symlink_to(self.systemd)
        self.fields = ['S', '1'] + ['0'] * 20; self.fields[19] = '42'
        self.parent_fields = ['S', '0'] + ['0'] * 20; self.parent_fields[19] = '6'
        (self.parent / 'stat').write_text('1 (systemd) ' + ' '.join(self.parent_fields))
        self.collector = Collector(1001, proc=self.proc)
        policy = replace(profile_fixture.PROFILE, maintenance_exe=str(self.binary),
                         maintenance_alias=str(self.alias), maintenance_unit=str(self.unit),
                         systemd_exe=str(self.systemd))
        self.enterContext(patch.object(observer, 'current', return_value=policy))

    def identify(self, **change):
        values = dict(proc=self.pid, uid=1001, exe=str(self.binary), comm='ampinstmgr',
                      roots=(), fields=self.fields, cg='0::/system.slice/amptasks.service\n')
        return self.collector.maintenance_identity(**{**values, **change})

    def test_protected_binary_unit_and_parent_identify(self):
        self.assertRegex(self.identify(), '^[0-9a-f]{64}$')

    def test_group_or_world_writable_binary_or_unit_refused(self):
        for p in [self.binary, self.unit, self.systemd]:
            old = p.stat().st_mode & 0o777
            for mode in [0o775, 0o757]:
                p.chmod(mode)
                with self.subTest(path=p.name, mode=mode): self.assertEqual(self.identify(), '')
            p.chmod(old)

    def test_nonroot_binary_unit_or_parent_refused(self):
        for p in [self.binary, self.unit, self.parent]:
            os.chown(p, 1001, -1)
            with self.subTest(path=p.name): self.assertEqual(self.identify(), '')
            os.chown(p, 0, -1)

    def test_alias_or_proc_executable_replacement_refused(self):
        self.alias.unlink(); self.alias.symlink_to(self.systemd)
        self.assertEqual(self.identify(), '')
        self.alias.unlink(); self.alias.symlink_to(self.binary)
        (self.pid / 'exe').unlink(); (self.pid / 'exe').symlink_to(self.systemd)
        self.assertEqual(self.identify(), '')

    def test_symlink_unit_and_parent_spoof_refused(self):
        self.unit.unlink(); self.unit.symlink_to(self.binary)
        self.assertEqual(self.identify(), '')
        self.unit.unlink(); self.unit.write_bytes(b'unit'); self.unit.chmod(0o644)
        (self.parent / 'stat').write_text('1 (spoofed) ' + ' '.join(self.parent_fields))
        self.assertEqual(self.identify(), '')

    def test_file_change_during_identity_acquisition_refused(self):
        original = self.collector.protected_identity
        calls = 0
        def changed(path):
            nonlocal calls
            value = original(path)
            if str(path) == str(self.unit):
                calls += 1
                if calls > 1: return (*value[:-1], value[-1] + 1)
            return value
        with patch.object(self.collector, 'protected_identity', changed):
            self.assertEqual(self.identify(), '')


class MaintenanceBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_observer_accepts_only_busy_maintenance_label(self):
        value = Verdict('busy', 'amp_maintenance', True, False, 0, 'a' * 32).public()
        with patch('discord_amp.services.rpc', AsyncMock(return_value=value)):
            result = await observer_call('fixture')
        self.assertEqual((result.state, result.reason), ('busy', 'amp_maintenance'))
        for change in [dict(state='clear'), dict(covered=False), dict(state='unknown')]:
            with self.subTest(change=change), patch('discord_amp.services.rpc', AsyncMock(return_value={**value, **change})):
                self.assertEqual((await observer_call('fixture')).state, 'unknown')

    async def test_broker_maintenance_refusal_has_zero_lifecycle_calls_and_no_replay(self):
        for has_controller in [True, False]:
            with self.subTest(has_controller=has_controller):
                directory = self.enterContext(tempfile.TemporaryDirectory())
                clock = Clock(); store = Store(directory, clock=clock)
                self.addCleanup(store.close)
                backend = Backend('stopped' if has_controller else 'controller_stopped', has_controller)
                observe = AsyncMock(return_value=Verdict('busy', 'amp_maintenance', True, False, 0, 'a' * 32))
                broker = Broker(backend, observe, store, lambda: True, clock)
                job = str(uuid.uuid4())
                with self.assertRaises(Fault) as error: await broker.start(job, OWNER)
                self.assertEqual(error.exception.code, 'guard_maintenance')
                self.assertEqual((store.get(job)['state'], store.get(job)['code']), ('blocked', 'guard_maintenance'))
                with self.assertRaises(Fault) as duplicate:
                    await broker.start(job, OWNER)
                self.assertEqual(duplicate.exception.code, 'guard_maintenance')
                self.assertEqual(backend.calls, ['status'])
                self.assertFalse(store.unresolved())

    async def test_disabled_gate_still_rejects_before_observation(self):
        with self.subTest('disabled gate'):
            directory = self.enterContext(tempfile.TemporaryDirectory())
            store = Store(directory); self.addCleanup(store.close)
            backend = Backend(); observe = AsyncMock()
            with self.assertRaises(Fault) as error:
                await Broker(backend, observe, store).start(str(uuid.uuid4()), OWNER)
            self.assertEqual(error.exception.code, 'mutations_disabled')
            observe.assert_not_awaited(); self.assertEqual(backend.calls, [])

    async def test_controller_retains_maintenance_code_and_conservative_hold(self):
        with self.subTest('controller code propagation'):
            directory = self.enterContext(tempfile.TemporaryDirectory())
            clock = Clock(); store = Store(directory, clock=clock); self.addCleanup(store.close)
            backend = Backend('stopped')
            backend.start = AsyncMock(side_effect=Fault('guard_maintenance'))
            wake, query = AsyncMock(), AsyncMock()
            controller = Controller(store, backend, wake, query, lambda: True, clock, clock.sleep)
            req = request(); await controller.submit(req)
            await asyncio.gather(*tuple(controller.tasks))
            self.assertEqual((store.get(req.id)['state'], store.get(req.id)['code']), ('unknown', 'guard_maintenance'))
            self.assertTrue(store.unresolved())
            wake.assert_not_awaited(); query.assert_not_awaited()
            backend.start.assert_awaited_once()
            self.assertEqual((await controller.submit(req))['code'], 'guard_maintenance')
            self.assertEqual(backend.start.await_count, 1)
            self.assertIn('AMP maintenance', MESSAGES['guard_maintenance'])


@unittest.skipUnless(sys.platform == 'linux', 'Native SO_PEERCRED transport')
class NativeMaintenanceIPCTests(unittest.IsolatedAsyncioTestCase):
    async def test_busy_label_crosses_real_observer_socket_and_denies_broker(self):
        directory = self.enterContext(tempfile.TemporaryDirectory(prefix='amp-task-ipc-'))
        store = Store(Path(directory) / 'journal'); self.addCleanup(store.close)
        path = str(Path(directory) / 'observer.sock')
        async def handler(message):
            self.assertEqual(message, {'operation': 'observe'})
            return Verdict('busy', 'amp_maintenance', True, False, 0, 'a' * 32).public()
        server = await serve_unix(path, os.geteuid(), handler)
        try:
            async def observe(): return await observer_call(path, os.geteuid())
            backend = Backend('stopped')
            broker = Broker(backend, observe, store, lambda: True)
            with self.assertRaises(Fault) as error: await broker.start(str(uuid.uuid4()), OWNER)
            self.assertEqual(error.exception.code, 'guard_maintenance')
            self.assertEqual(backend.calls, ['status'])
        finally:
            server.close(); await server.wait_closed()
            await asyncio.sleep(0)
            await asyncio.gather(*tuple(server.client_tasks))


@unittest.skipUnless(importlib.util.find_spec('discord'), 'Pinned discord.py frontend dependency')
class MaintenanceFrontendTests(unittest.IsolatedAsyncioTestCase):
    async def test_private_game_start_reply_names_maintenance(self):
        import discord
        from discord_amp.bot import build_client
        from profile_fixture import GUILD, CHANNEL, APPLICATION
        client = build_client('unused-test-token', 'fixture-socket', 123)
        try:
            member = MagicMock(spec=discord.Member); member.id = int(OWNER); member.roles = []
            interaction = SimpleNamespace(id=1561200000000000000, user=member, guild_id=int(GUILD),
                channel_id=int(CHANNEL), application_id=int(APPLICATION),
                response=SimpleNamespace(defer=AsyncMock(), send_message=AsyncMock()), edit_original_response=AsyncMock())
            command = client.tree.get_command('game', guild=discord.Object(id=int(GUILD))).get_command('start')
            job = str(uuid.uuid4())
            with patch('discord_amp.bot.rpc', AsyncMock(side_effect=[
                {'job': job, 'code': 'accepted'}, {'job': job, 'code': 'guard_maintenance', 'terminal': True}])), \
                    patch('discord_amp.bot.asyncio.sleep', AsyncMock()):
                await command.callback(interaction, 'enshrouded')
            interaction.response.defer.assert_awaited_once_with(ephemeral=True, thinking=True)
            self.assertEqual(interaction.edit_original_response.call_args.kwargs['content'],
                             f'Job {job}: AMP maintenance tasks are active. Start refused.')
        finally:
            await client.close()


if __name__ == '__main__':
    unittest.main()
