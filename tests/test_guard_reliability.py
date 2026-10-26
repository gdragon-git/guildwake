import profile_fixture
"""Exact guard/broker/controller paths with owned fixtures, never real AMP/WOL.

Windows replaces only Linux proc/Unix/peer boundaries. Linux additionally uses
real Unix IPC and positively owned kernel process fixtures. Local TCP is loopback.
"""
import asyncio
from contextlib import ExitStack
from dataclasses import asdict, replace
import errno
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import AsyncMock, patch

from discord_amp import observer, services, wire
from discord_amp.broker import Broker
from discord_amp.controller import Controller
from discord_amp.guard import assess, Verdict
from discord_amp.model import Fault, Request, StartBlocked
from profile_fixture import APPLICATION, CHANNEL, GAME, GUILD, INSTANCE, INSTANCES, OWNER, ROLE
from discord_amp.store import Store


class Clock:
    def __init__(self): self.value = 1000.0
    def __call__(self): return self.value
    async def sleep(self, seconds): self.value += seconds; await asyncio.sleep(0)


def process(**change):
    return {**dict(uid=0, exe='/usr/bin/sleep', cwd='/', cg='0::/system.slice/fixture.service\n',
                   ticks=42, state='S', flags=0, management=False, maintenance=False), **change}


class ProcPath:
    """Controlled proc boundary. No disk IO or invented permissive scan result."""
    def __init__(self, fixture, parts=()): self.fixture, self.parts = fixture, parts
    def __truediv__(self, child): return ProcPath(self.fixture, self.parts + tuple(str(child).split('/')))
    def __fspath__(self): return '/controlled-proc/' + '/'.join(self.parts)
    @property
    def name(self): return self.parts[-1]
    def iterdir(self): return iter(self / str(pid) for pid in self.fixture.plan.get('rows', {}))
    def stat(self):
        if len(self.parts) == 1:
            return SimpleNamespace(st_uid=self.fixture.read(int(self.parts[0]), 'owner'))
        if self.parts[1:] == ('root', 'AMP'):
            name = self.fixture.plan['rows'][int(self.parts[0])].get('mapped')
            if name not in INSTANCES: raise FileNotFoundError(errno.ENOENT, 'fixture_unmapped_container')
            return SimpleNamespace(st_dev=1, st_ino=list(INSTANCES).index(name) + 1)
        raise AssertionError('unexpected_fixture_stat')
    def read_text(self):
        if self.parts == ('sys', 'kernel', 'random', 'boot_id'): return 'fixture-boot'
        pid, kind = int(self.parts[0]), self.parts[1]
        value = self.fixture.read(pid, kind)
        if kind == 'stat':
            fields = [value['state'], '1'] + ['0'] * 20
            fields[6], fields[19] = str(value['flags']), str(value['ticks'])
            return f'{pid} (fixture) ' + ' '.join(fields)
        return value


class ProcFixture:
    def __init__(self, plans, collector_type=observer.Collector):
        self.plans, self.clock, self.calls = plans, Clock(), []
        self.plan, self.reads = {}, {}
        fixture = self

        class Acquisition(collector_type):
            def inventory(self):
                failure = fixture.plan.get('inventory_failure')
                if failure: raise failure
                return 'fixture-inventory', {name: (1, i + 1) for i, name in enumerate(INSTANCES)}
            def membership(self): return fixture.plan.get('members', {})
            def maintenance_identity(self, proc, *args):
                return 'protected-fixture-task' if fixture.plan['rows'][int(proc.name)]['maintenance'] else ''
            def management(self, proc, *args): return fixture.plan['rows'][int(proc.name)]['management']
            def scan(self):
                index = len(fixture.calls)
                if index >= len(fixture.plans): raise AssertionError('unexpected_extra_scan')
                fixture.plan, fixture.reads = fixture.plans[index], {}
                value = super().scan()
                fixture.calls.append(value)
                fixture.clock.value += fixture.plan.get('elapsed', .01)
                return value

        self.collector = Acquisition(1001, proc=ProcPath(self))
        self.collector.now = self.clock

    def read(self, pid, kind):
        key = (pid, kind)
        self.reads[key] = self.reads.get(key, 0) + 1
        special = self.plan.get('events', {}).get((*key, self.reads[key]))
        if isinstance(special, BaseException): raise special
        row = self.plan['rows'][pid]
        value = row['uid'] if kind == 'owner' else row if kind == 'stat' else row['cg' if kind == 'cgroup' else kind]
        return special if special is not None else value

    def readlink(self, path): return self.read(int(path.parts[0]), path.parts[1])
    def verdict(self):
        with patch.object(observer.os, 'readlink', self.readlink):
            return self.collector.verdict()


def plan(rows=None, **change): return dict(rows={10: process()} if rows is None else rows, **change)
def gone(kind='owner', occurrence=1):
    return plan(events={(10, kind, occurrence): FileNotFoundError(errno.ENOENT, 'declared_process_exit')})


class AcquisitionReliabilityTests(unittest.TestCase):
    def test_transient_exit_requires_an_entire_new_pair(self):
        fixture = ProcFixture([gone(), plan(), plan(), plan()])
        result = fixture.verdict()
        self.assertEqual((result.state, result.covered), ('clear', True))
        self.assertEqual(len(fixture.calls), 4)
        self.assertEqual(fixture.calls[0]['errors'], ['process_turnover'])
        self.assertEqual([row['errors'] for row in fixture.calls[2:]], [[], []])

    def test_all_dynamic_read_boundaries_and_rechecks(self):
        for kind in ('owner', 'stat', 'exe', 'cwd', 'cgroup'):
            for occurrence in (1, 2):
                with self.subTest(kind=kind, occurrence=occurrence):
                    fixture = ProcFixture([gone(kind, occurrence), plan(), plan(), plan()])
                    self.assertEqual(fixture.verdict().state, 'clear')
                    self.assertEqual(len(fixture.calls), 4)

    def test_sustained_churn_remains_unknown_and_bounded(self):
        fixture = ProcFixture([gone(), gone(), gone(), gone()])
        self.assertEqual(fixture.verdict().state, 'unknown')
        self.assertEqual(len(fixture.calls), 4)

    def test_no_reacquisition_after_static_permission_or_identity_failure(self):
        changed = process(); changed['ticks'] = 43
        variations = [plan(inventory_failure=FileNotFoundError()),
                      plan(events={(10, 'owner', 1): PermissionError()}),
                      plan(events={(10, 'stat', 2): changed}),
                      plan(rows={10: {**process(), 'state': 'Z'}})]
        for first in variations:
            with self.subTest(first=first):
                fixture = ProcFixture([first, plan()])
                self.assertEqual(fixture.verdict().state, 'unknown')
                self.assertEqual(len(fixture.calls), 2)

    def test_busy_unknown_or_selected_game_is_not_erased_by_a_torn_pair(self):
        for row in [process(uid=1001), process(cwd=INSTANCES['ARKSurvivalAscended01'][1]),
                    process(uid=1001, maintenance=True), process(cwd=INSTANCES[INSTANCE][1])]:
            with self.subTest(row=row):
                fixture = ProcFixture([gone(), plan(rows={20: row})])
                self.assertEqual(fixture.verdict().state, 'unknown')
                self.assertEqual(len(fixture.calls), 2)

    def test_complete_busy_unknown_and_clear_pairs_are_not_retried(self):
        for row, expected in [(process(), 'clear'), (process(uid=1001), 'unknown'),
                              (process(cwd=INSTANCES['ZomboidLAN01'][1]), 'busy'),
                              (process(uid=1001, maintenance=True), 'busy')]:
            with self.subTest(expected=expected, row=row):
                fixture = ProcFixture([plan({20: row}), plan({20: row})])
                self.assertEqual(fixture.verdict().state, expected)
                self.assertEqual(len(fixture.calls), 2)

    def test_container_mapping_and_membership_failures_are_not_turnover(self):
        for row in [process(mapped=None), process(mapped=INSTANCE)]:
            with self.subTest(row=row):
                fixture = ProcFixture([plan({10: row}, members={'docker-fixture.scope': {10}}), plan()])
                self.assertEqual(fixture.verdict().state, 'unknown')
                self.assertEqual(len(fixture.calls), 2)

    def test_budget_exhaustion_cannot_start_a_second_pair(self):
        fixture = ProcFixture([{**gone(), 'elapsed': .6}, plan(elapsed=.6)])
        self.assertEqual(fixture.verdict().state, 'unknown')
        self.assertEqual(len(fixture.calls), 2)

    def test_new_pair_cannot_merge_changed_relevant_identities(self):
        row = process(cwd=INSTANCES[INSTANCE][1], exe='/AMP/AMP_Linux_x86_64')
        later = {**row, 'ticks': 99}
        fixture = ProcFixture([gone(), plan(), plan({20: row}), plan({20: later})])
        self.assertEqual(fixture.verdict().state, 'unknown')
        self.assertEqual(len(fixture.calls), 4)

    def test_deployed_error_reporter_constructor_and_safe_failure_record_are_preserved(self):
        records = []
        fixture = ProcFixture([gone(), plan(), plan(), plan()])
        fixture.collector.error_reporter = lambda value: records.append(value) or True
        self.assertEqual(fixture.verdict().state, 'clear')
        self.assertEqual(len(records), 1)
        self.assertEqual((records[0]['stage'], records[0]['type'], records[0]['errno'], records[0]['pid']),
                         ('process_owner', 'FileNotFoundError', 2, 10))
        self.assertEqual(set(records[0]), {'stage', 'type', 'code', 'errno', 'pid', 'start_ticks', 'process_state'})
        self.assertEqual(fixture.collector.last_failure, records[0])
        self.assertFalse(fixture.collector.reporting_failed)
        constructed = observer.Collector(1001, error_reporter=lambda value: True)
        self.assertIsNotNone(constructed.error_reporter)


class ReceiptTests(unittest.TestCase):
    def test_exact_bound_receipt_only(self):
        identity = str(uuid.uuid4())
        value = StartBlocked(identity, OWNER, 'guard_unknown').public()
        result = StartBlocked.parse(value, identity, OWNER)
        self.assertEqual((result.identity, result.user, result.code), (identity, OWNER, 'guard_unknown'))
        for change in [dict(id=str(uuid.uuid4())), dict(user='123456789123456789'),
                       dict(effect_attempted=True), dict(effect_attempted=0), dict(state='unknown'),
                       dict(code='starting'), dict(code=[]), dict(extra='ignored')]:
            with self.subTest(change=change), self.assertRaises(Fault):
                StartBlocked.parse({**value, **change}, identity, OWNER)


class HarmlessAMP:
    def __init__(self, mode='normal', state='stopped', controller=True):
        self.mode, self.state, self.controller = mode, state, controller
        self.effects, self.status_calls, self.entered = [], 0, asyncio.Event()
        self.before_send = lambda: None
    async def status(self):
        self.status_calls += 1
        return {'controller': self.controller, 'state': self.state}
    async def mutate(self, permit, kind):
        self.before_send()
        permit()
        self.effects.append(kind); self.entered.set()
        if self.mode == 'lost': raise OSError('declared_lost_reply')
        if self.mode == 'post-send-code': raise Fault('guard_unknown')
        if self.mode == 'cancel': await asyncio.Event().wait()
        self.controller, self.state = True, 'ready'
    async def start_application(self, permit): await self.mutate(permit, 'application')
    async def start_child(self, permit): await self.mutate(permit, 'child')


def request(number=1, action='start', **change):
    value = dict(interaction=str(1563000000000000000 + number), user='123456789123456789',
                 guild=GUILD, channel=CHANNEL, application=APPLICATION, roles=(ROLE,),
                 action=action, target=GAME if action == 'start' else 'gameserver')
    return Request(**{**value, **change})


class FullPathTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='guard-reliability-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = Clock(); self.wakes = []; self.queries = []
        self.control_store = Store(self.root / 'controller', clock=self.clock)
        self.addCleanup(self.control_store.close)
        self.broker_store = Store(self.root / 'broker', clock=self.clock)
        self.addCleanup(self.broker_store.close)
        self.amp = HarmlessAMP()
        self.fixture = ProcFixture([plan(), plan()])
        self.collector_calls = []
        self.broker_enabled = True
        self.controller_enabled = True
        self.broker = Broker(self.amp, self.observe, self.broker_store, lambda: self.broker_enabled, self.clock)
        self.http = await services.broker_http(self.broker, 'fixture-token-only', port=0)
        self.port = self.http.sockets[0].getsockname()[1]
        self.connections = []
        original = asyncio.open_connection
        async def open_fixture(path, **kwargs):
            if path != 'fixture-only-broker.sock': raise AssertionError('unexpected_socket_target')
            pair = await original('127.0.0.1', self.port, **kwargs)
            self.connections.append(pair[1]); return pair
        self.enterContext(patch('discord_amp.wire.asyncio.open_unix_connection', open_fixture, create=True))
        self.client = services.BrokerClient('fixture-only-broker.sock', 'fixture-token-only')
        self.control = Controller(self.control_store, self.client, self.wake, self.query,
                                  lambda: self.controller_enabled, self.clock, self.clock.sleep)

    async def asyncTearDown(self):
        for task in tuple(self.control.tasks): task.cancel()
        await asyncio.gather(*tuple(self.control.tasks), return_exceptions=True)
        self.http.close(); await self.http.wait_closed()
        for writer in self.connections: await wire.close_writer(writer)
        self.control_store.close(); self.broker_store.close(); self.temp.cleanup()

    async def wake(self): self.wakes.append('wake')
    async def query(self): self.queries.append('query'); return self.amp.state == 'ready'
    async def observe(self):
        # Actual observer handler and validation. Only proc and Linux RPC/peer
        # boundaries are controlled here; TCP HTTP/decoder/client/journals are real.
        async def rpc_fixture(path, message, uid, timeout):
            self.assertEqual((path, message, uid, timeout), ('fixture-observer.sock', {'operation': 'observe'}, 0, 2))
            return await services.observer_handler(SimpleNamespace(verdict=self.fixture.verdict), message)
        with patch('discord_amp.services.rpc', rpc_fixture):
            value = await services.observer_call('fixture-observer.sock')
        self.collector_calls.append(value)
        return value

    async def submit(self, req=None):
        req = req or request()
        message = {'operation': 'submit', 'request': {**asdict(req), 'roles': list(req.roles)}}
        accepted = await services.controller_handler(self.control, message)
        if self.control.tasks: await asyncio.gather(*tuple(self.control.tasks))
        progress = await services.controller_handler(self.control, {**message, 'operation': 'progress', 'job': accepted['job']})
        return req, progress

    async def test_turnover_recovers_before_one_effect_and_duplicates_do_not_replay(self):
        self.fixture = ProcFixture([gone(), plan(), plan(), plan()])
        req, result = await self.submit()
        self.assertEqual((result['code'], result['terminal']), ('ready', True))
        self.assertEqual(self.amp.effects, ['application'])
        self.assertEqual(len(self.fixture.calls), 4)
        duplicate = await self.control.submit(req)
        self.assertEqual(duplicate['job'], req.id)
        self.assertEqual(self.amp.effects, ['application'])
        self.assertFalse(self.control_store.unresolved()); self.assertFalse(self.broker_store.unresolved())

    async def assert_block(self, expected):
        req, result = await self.submit()
        self.assertEqual(result['code'], expected)
        self.assertEqual(self.amp.effects + self.wakes + self.queries, [])
        for store in (self.control_store, self.broker_store):
            self.assertEqual((store.get(req.id)['state'], store.get(req.id)['code']), ('blocked', expected))
            self.assertFalse(store.unresolved())
        duplicate = await self.control.submit(req)
        self.assertEqual((duplicate['job'], duplicate['code']), (req.id, expected))
        with self.assertRaises(StartBlocked): await self.client.start(req.id, req.user)
        self.assertEqual(self.amp.effects, [])
        # Explicit later requests remain subject to the unchanged cooldown.
        with self.assertRaises(Fault) as cooldown: await self.control.submit(request(2))
        self.assertEqual(cooldown.exception.code, 'cooldown')
        return req

    async def test_sustained_turnover_is_zero_effect_block_without_false_review_hold(self):
        self.fixture = ProcFixture([gone(), gone(), gone(), gone()])
        await self.assert_block('guard_unknown')

    async def test_other_game_busy_still_blocks(self):
        rows = {20: process(cwd=INSTANCES['ARKSurvivalAscended01'][1])}
        self.fixture = ProcFixture([plan(rows), plan(rows)])
        await self.assert_block('guard_busy')

    async def test_active_maintenance_still_blocks(self):
        rows = {20: process(uid=1001, maintenance=True)}
        self.fixture = ProcFixture([plan(rows), plan(rows)])
        await self.assert_block('guard_maintenance')

    async def test_unclassified_amp_activity_still_blocks(self):
        rows = {20: process(uid=1001)}
        self.fixture = ProcFixture([plan(rows), plan(rows)])
        await self.assert_block('guard_unknown')

    async def test_verified_wake_then_start_refusal_settles_without_an_uncertain_start(self):
        self.fixture = ProcFixture([gone(), gone(), gone(), gone()])
        original = self.client.status
        calls = 0
        async def asleep_once():
            nonlocal calls
            calls += 1
            if calls == 1: raise Fault('broker_unavailable')
            return await original()
        with patch.object(self.client, 'status', asleep_once):
            req, result = await self.submit()
        self.assertEqual((result['code'], self.control_store.get(req.id)['state']), ('guard_unknown', 'blocked'))
        self.assertEqual(self.wakes, ['wake'])
        self.assertEqual(self.amp.effects, [])
        self.assertFalse(self.control_store.unresolved())

    async def test_uncertain_wake_never_becomes_a_confirmed_start_refusal(self):
        async def failed_wake(): self.wakes.append('wake'); raise OSError('declared_wake_reply_loss')
        with patch.object(self.client, 'status', AsyncMock(side_effect=Fault('broker_unavailable'))):
            self.control.wake = failed_wake
            req, _ = await self.submit()
        self.assertEqual(self.control_store.get(req.id)['state'], 'unknown')
        self.assertTrue(self.control_store.unresolved())
        self.assertEqual(self.amp.effects, [])

    async def test_child_start_autostart_is_one_effect(self):
        self.amp.state, self.amp.controller = 'controller_stopped', False
        await self.submit()
        self.assertEqual(self.amp.effects, ['child'])

    async def test_concurrent_requests_share_one_job_and_one_effect(self):
        first, second = await asyncio.gather(self.control.submit(request()), self.control.submit(request(2)))
        self.assertEqual(first['job'], second['job'])
        if self.control.tasks: await asyncio.gather(*tuple(self.control.tasks))
        self.assertEqual(self.amp.effects, ['application'])
        self.assertEqual(len(self.collector_calls), 1)

    async def test_dropped_http_reply_holds_controller_and_does_not_repeat_a_successful_dispatch(self):
        original_port = self.port
        tasks = set()
        async def drop_start(reader, writer):
            task = asyncio.current_task(); tasks.add(task)
            upstream = None
            try:
                headers = await reader.readuntil(b'\r\n\r\n')
                lines = headers.decode('ascii').split('\r\n')
                size = int(next(line.split(':', 1)[1] for line in lines if line.lower().startswith('content-length:')))
                body = await reader.readexactly(size)
                response, upstream = await asyncio.open_connection('127.0.0.1', original_port)
                upstream.write(headers + body); await upstream.drain()
                raw = await response.read(8192)
                if ' /v1/start ' not in lines[0]:
                    writer.write(raw); await writer.drain()
            finally:
                if upstream is not None: await wire.close_writer(upstream)
                await wire.close_writer(writer); tasks.discard(task)
        relay = await asyncio.start_server(drop_start, '127.0.0.1', 0)
        self.port = relay.sockets[0].getsockname()[1]
        try:
            req, result = await self.submit()
            self.assertEqual(result['code'], 'unknown')
            self.assertTrue(self.control_store.unresolved())
            self.assertEqual(self.broker_store.get(req.id)['state'], 'complete')
            await self.control.submit(req)
            self.assertEqual(self.amp.effects, ['application'])
        finally:
            relay.close(); await relay.wait_closed()
            if tasks: await asyncio.gather(*tuple(tasks))

    async def test_cancellation_during_a_possible_send_remains_unknown(self):
        async def wait_after_dispatch(identity, user):
            self.amp.effects.append('application'); self.amp.entered.set()
            await asyncio.Event().wait()
        with patch.object(self.client, 'start', wait_after_dispatch):
            req = request()
            await self.control.submit(req)
            await asyncio.wait_for(self.amp.entered.wait(), 2)
            task = next(iter(self.control.tasks)); task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(self.control_store.get(req.id)['state'], 'unknown')
        self.assertTrue(self.control_store.unresolved())
        await self.control.submit(req)
        self.assertEqual(self.amp.effects, ['application'])

    async def test_already_running_and_awake_wake_are_read_only(self):
        self.amp.state = 'ready'
        await self.submit()
        self.clock.value += 61
        await self.submit(request(2, 'wake'))
        self.assertEqual(self.amp.effects + self.wakes, [])
        self.assertEqual(self.collector_calls, [])

    async def test_status_remains_available_after_known_guard_refusal(self):
        self.fixture = ProcFixture([gone(), gone(), gone(), gone()])
        await self.submit()
        req, result = await self.submit(request(2, 'status'))
        self.assertEqual(result['code'], 'stopped')
        self.assertEqual(self.control_store.get(req.id)['state'], 'complete')
        self.assertEqual(self.amp.effects + self.wakes, [])

    async def test_lost_reply_retains_both_holds_without_replay(self):
        self.amp.mode = 'lost'
        req, result = await self.submit()
        self.assertEqual(result['code'], 'unknown')
        self.assertTrue(self.control_store.unresolved()); self.assertTrue(self.broker_store.unresolved())
        self.assertEqual(self.amp.effects, ['application'])
        await self.control.submit(req)
        self.clock.value += 61
        with self.assertRaises(Fault): await self.control.submit(request(99))

    async def test_post_send_guard_code_is_not_a_no_effect_receipt(self):
        self.amp.mode = 'post-send-code'
        req, result = await self.submit()
        self.assertEqual(result['code'], 'guard_unknown')
        self.assertTrue(self.control_store.unresolved()); self.assertTrue(self.broker_store.unresolved())
        self.assertEqual(self.amp.effects, ['application'])

    async def test_expiry_after_attempt_marker_remains_conservative_even_with_zero_effects(self):
        def expire(): self.clock.value += 3
        self.amp.before_send = expire
        req, result = await self.submit()
        self.assertEqual(result['code'], 'guard_unknown')
        self.assertTrue(self.control_store.unresolved()); self.assertTrue(self.broker_store.unresolved())
        self.assertEqual(self.amp.effects, [])

    async def test_legacy_code_only_refusal_remains_conservative(self):
        with patch.object(self.client, 'start', AsyncMock(side_effect=Fault('guard_unknown'))):
            req, _ = await self.submit()
        self.assertEqual(self.control_store.get(req.id)['state'], 'unknown')
        self.assertTrue(self.control_store.unresolved())
        self.assertEqual(self.amp.effects, [])

    async def test_mismatched_receipt_never_releases_a_hold(self):
        bad = StartBlocked(str(uuid.uuid4()), OWNER, 'guard_unknown')
        with patch.object(self.client, 'start', AsyncMock(side_effect=bad)):
            req, _ = await self.submit()
        self.assertEqual(self.control_store.get(req.id)['state'], 'unknown')

    async def test_disabled_controller_gate_prevents_host_contact(self):
        self.controller_enabled = False
        with self.assertRaises(Fault) as error: await self.control.submit(request())
        self.assertEqual(error.exception.code, 'mutations_disabled')
        self.assertEqual(self.amp.status_calls, 0)

    async def test_broker_gate_closing_after_observation_is_a_durable_block(self):
        original = self.broker.observe
        async def close_gate():
            value = await original(); self.broker_enabled = False; return value
        self.broker.observe = close_gate
        await self.assert_block('mutations_disabled')

    async def test_persistence_failure_cannot_emit_a_blocked_receipt(self):
        self.fixture = ProcFixture([gone(), gone(), gone(), gone()])
        original = self.broker_store.update
        def fail_block(identity, state, code, stage=None):
            if state == 'blocked': raise Fault('audit_unavailable')
            return original(identity, state, code, stage)
        with patch.object(self.broker_store, 'update', fail_block):
            req, _ = await self.submit()
        self.assertEqual(self.control_store.get(req.id)['state'], 'unknown')
        self.assertTrue(self.control_store.unresolved()); self.assertTrue(self.broker_store.unresolved())
        self.assertEqual(self.amp.effects, [])

    async def test_role_channel_and_command_failures_never_contact_broker(self):
        for change in (dict(roles=()), dict(channel='123456789123456788'), dict(target='ark')):
            with self.subTest(change=change), self.assertRaises(Fault):
                await self.control.submit(request(**change))
        self.assertEqual(self.amp.status_calls, 0)

    async def test_wrong_http_token_cannot_obtain_a_trusted_receipt(self):
        self.client.token = 'wrong-fixture-token'
        with self.assertRaises(Fault) as error: await self.client.start(request().id, request().user)
        self.assertEqual(error.exception.code, 'broker_rejected')
        self.assertEqual(self.amp.status_calls, 0)

    async def test_blocked_receipt_framing_and_binding_are_validated_at_the_real_client(self):
        req = request()
        receipt = StartBlocked(req.id, req.user, 'guard_unknown').public()
        for change in [dict(user=OWNER), dict(id=str(uuid.uuid4())), dict(effect_attempted=0), dict(extra=True)]:
            with self.subTest(change=change), patch('discord_amp.services.http_request', AsyncMock(return_value={**receipt, **change})):
                with self.assertRaises(Fault) as error: await self.client.start(req.id, req.user)
                self.assertNotIsInstance(error.exception, StartBlocked)

    async def test_reopened_journals_do_not_replay_uncertain_effect(self):
        self.amp.mode = 'lost'
        req, _ = await self.submit()
        other = Store(self.root / 'controller', clock=self.clock)
        try:
            clone = Controller(other, self.client, self.wake, self.query, lambda: True)
            await clone.recover()
            self.assertTrue(other.unresolved())
            self.assertEqual(self.amp.effects, ['application'])
            self.assertEqual(self.wakes, [])
            self.assertEqual(other.get(req.id)['state'], 'unknown')
        finally: other.close()

    async def test_reopened_journal_preserves_known_block_without_effect_or_hold(self):
        self.fixture = ProcFixture([gone(), gone(), gone(), gone()])
        req, _ = await self.submit()
        other = Store(self.root / 'controller', clock=self.clock)
        try:
            clone = Controller(other, self.client, self.wake, self.query, lambda: True)
            before = self.amp.status_calls
            await clone.recover()
            self.assertFalse(other.unresolved())
            self.assertEqual((other.get(req.id)['state'], self.amp.status_calls), ('blocked', before))
            self.assertEqual(self.amp.effects + self.wakes, [])
        finally: other.close()


@unittest.skipUnless(sys.platform == 'linux', 'Native Linux kernel/Unix IPC proof, not Windows local proof')
class NativeBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_owned_proc_pairs_reacquire_and_keep_relevant_work_blocking(self):
        # A deliberately scoped view of positively owned test processes. It is
        # not a claim that a filtered production proc inventory covers a host.
        with tempfile.TemporaryDirectory(prefix='guard-proc-') as temp:
            root = Path(temp)
            paths = {name: (ident, str(root / name)) for name, (ident, _) in INSTANCES.items()}
            for _, path in paths.values(): Path(path).mkdir()
            live = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(10)'],
                                    cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            dead = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'pass'],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            dead.wait(timeout=2)
            class View:
                def __init__(self): self.calls = 0
                def __truediv__(self, child): return Path('/proc') / str(child)
                def iterdir(self):
                    self.calls += 1
                    pids = [dead.pid, live.pid] if self.calls == 1 else [live.pid]
                    return iter(Path('/proc') / str(pid) for pid in pids)
            class OwnedCollector(observer.Collector):
                def inventory(self):
                    return 'owned-fixture-only', {name: self.inode(Path(path)) for name, (_, path) in paths.items()}
                def membership(self): return {}
            try:
                view = View()
                collector = OwnedCollector(-1, proc=view)
                value = collector.verdict()
                self.assertEqual((value.state, value.covered, view.calls), ('clear', True, 4))
                self.assertEqual(collector.last_failure['pid'], dead.pid)
                unknown = OwnedCollector(os.geteuid(), proc=View())
                # The second complete scan sees a real unclassified UID: it
                # must not be erased by the first torn scan.
                self.assertEqual(unknown.verdict().state, 'unknown')
                game = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(10)'],
                    cwd=paths['ARKSurvivalAscended01'][1], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    class GameView(View):
                        def iterdir(self): return iter([Path('/proc') / str(game.pid)])
                    with patch.object(observer, 'current', return_value=replace(profile_fixture.PROFILE, instances=paths)):
                        self.assertEqual(OwnedCollector(-1, proc=GameView()).verdict().state, 'busy')
                finally:
                    game.terminate(); game.wait(timeout=2)
                self.assertIsNone(live.poll())
            finally:
                if live.poll() is None: live.terminate()
                live.wait(timeout=2)

    async def test_real_observer_unix_peer_and_broker_receipt(self):
        with tempfile.TemporaryDirectory(prefix='guard-native-') as directory:
            store = Store(Path(directory) / 'journal')
            fixture = ProcFixture([gone(), gone(), gone(), gone()])
            path = Path(directory) / 'observer.sock'
            server = await wire.serve_unix(path, os.geteuid(),
                lambda message: services.observer_handler(SimpleNamespace(verdict=fixture.verdict), message))
            try:
                verdict = await services.observer_call(str(path), os.geteuid())
                self.assertEqual(verdict.state, 'unknown')
                amp = HarmlessAMP()
                broker = Broker(amp, AsyncMock(return_value=verdict), store, lambda: True)
                with self.assertRaises(StartBlocked): await broker.start(request().id, request().user)
                self.assertEqual(amp.effects, [])
            finally:
                server.close(); await server.wait_closed(); await asyncio.sleep(0)
                await asyncio.gather(*tuple(server.client_tasks), return_exceptions=True)
                store.close()

    async def test_real_owned_process_exit_is_typed_and_never_silently_ignored(self):
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(.1)'], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid = child.pid
        _, fields = observer.Collector.stat_fields(Path(f'/proc/{pid}/stat'))
        before = fields[19]
        child.wait(timeout=2)
        try:
            observer.process_read(lambda: Path(f'/proc/{pid}').stat())
        except observer.ProcessTurnover:
            pass
        else:
            # A reused numeric PID is a different identity, never the old child.
            _, after = observer.Collector.stat_fields(Path(f'/proc/{pid}/stat'))
            self.assertNotEqual(before, after[19])
        self.assertEqual(child.returncode, 0)


if __name__ == '__main__':
    unittest.main()
