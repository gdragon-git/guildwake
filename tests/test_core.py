import profile_fixture
import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from discord_amp.model import Request, Fault, decode
from profile_fixture import OWNER, ROLE, GUILD, CHANNEL, APPLICATION, INSTANCE
from discord_amp.store import Store
from discord_amp.broker import Broker
from discord_amp.controller import Controller
from discord_amp.guard import assess, Verdict
from discord_amp.network import parse_a2s
from discord_amp.services import broker_http, observer_call
from discord_amp.amp import AMP, Session


def request(action='start', target='enshrouded', number=0, **change):
    values = dict(interaction=str(1561200000000000000 + number), user=OWNER, guild=GUILD,
                  channel=CHANNEL, application=APPLICATION, roles=(), action=action, target=target)
    return Request(**{**values, **change})


class Clock:
    def __init__(self): self.value = 10000.
    def __call__(self): return self.value
    async def sleep(self, n): self.value += n; await asyncio.sleep(0)


class Backend:
    def __init__(self, state='stopped', controller=True):
        self.state, self.controller, self.calls = state, controller, []
        self.error, self.delay = None, None
    async def status(self):
        self.calls.append('status')
        if self.error: raise Fault(self.error)
        return {'state': self.state, 'controller': self.controller}
    async def start_child(self, permit_send):
        permit_send()
        self.calls.append('child'); self.controller = True; self.state = 'starting'
        if self.error: raise Fault(self.error)
    async def start_application(self, permit_send):
        permit_send()
        self.calls.append('application'); self.state = 'starting'
        if self.error: raise Fault(self.error)


class PolicyTests(unittest.TestCase):
    def test_owner_and_role(self):
        request().authorize()
        request(user='123456789123456789', roles=(ROLE,)).authorize()
    def test_denials(self):
        for change in [dict(user='123456789123456789'), dict(guild='123456789123456789'),
                       dict(channel='123456789123456789'), dict(application='123456789123456789'), dict(guild='None')]:
            with self.subTest(change=change), self.assertRaises(Fault): request(**change).authorize()
    def test_fixed_scope(self):
        for action, target in [('stop','enshrouded'),('start','ark'),('wake','192.0.2.10'),('status','enshrouded'),('sleep','gameserver')]:
            with self.subTest(action=action), self.assertRaises(Fault): request(action,target).authorize()
    def test_strict_request(self):
        value=asdict(request()); value['roles']=list(value['roles'])
        self.assertEqual(Request.parse(value).id,request().id)
        for change in [dict(user=123),dict(roles=None),dict(roles=['admin']),dict(extra='ignore')]:
            with self.subTest(change=change),self.assertRaises(Fault): Request.parse({**value,**change})
    def test_json_smuggling(self):
        for data in [b'{"a":1,"a":2}', b'{"a":NaN}',b'[]',b'x'*4097]:
            with self.subTest(data=data[:20]),self.assertRaises(Fault): decode(data)
    def test_stable_job_identity(self):
        self.assertEqual(request().id,request().id)
        self.assertNotEqual(request().id,request(number=1).id)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.clock=Clock()
        self.store=Store(self.temp.name,128*1024,self.clock); self.id=str(uuid.uuid4())
    def tearDown(self): self.store.close(); self.temp.cleanup()
    def test_durable_intent_and_dedup(self):
        self.store.create(self.id,'start',OWNER); self.store.update(self.id,'attempted','starting','child')
        self.assertEqual(self.store.create(self.id,'start',OWNER)['stage'],'child')
        other=Store(self.temp.name,128*1024,self.clock)
        self.assertEqual(other.get(self.id)['state'],'attempted'); other.close()
    def test_no_raw_api_or_error_text(self):
        self.store.create(self.id,'start',OWNER)
        with self.assertRaises(Fault): self.store.update(self.id,'failed','secret_password')
    def test_unknown_survives_retention(self):
        self.store.create(self.id,'start',OWNER); self.store.update(self.id,'unknown','unknown')
        self.clock.value+=31*86400; self.store.deny(OWNER,'cooldown')
        self.assertTrue(self.store.unresolved()); self.assertIsNotNone(self.store.get(self.id))
    def test_cap_blocks_before_intent(self):
        Path(self.temp.name,'unexpected').write_bytes(b'x'*(256*1024))
        with self.assertRaises(Fault): self.store.create(self.id,'start',OWNER)
        self.assertIsNone(self.store.get(self.id))
    def test_age_prunes_completed(self):
        self.store.create(self.id,'start',OWNER); self.store.update(self.id,'complete','ready')
        self.clock.value+=31*86400; self.store.deny(OWNER,'cooldown')
        self.assertIsNone(self.store.get(self.id))


def snapshot(start=100, rows=None):
    row=dict(start_ticks=200,instances=(INSTANCE,),stable=True,container=INSTANCE,
             fingerprint='example',management=False,application_activity=True)
    rows={123:row} if rows is None else rows
    return dict(start=start,end=start+.01,boot='boot',inventory_ok=True,inventory='inventory',errors=[],
                rows=rows,relevant_pids=tuple(rows),container_pids=tuple(p for p,r in rows.items() if r['container']),unmapped_containers=False)


class GuardTests(unittest.TestCase):
    def test_clear_only_selected(self):
        verdict=assess(snapshot(),snapshot(100.02),100.04,'boot')
        self.assertEqual(verdict.state,'clear'); self.assertTrue(verdict.selected_active)
    def test_other_orphan_blocks(self):
        rows={123:dict(start_ticks=20,instances=('ARKSurvivalAscended01',),stable=True,container=None,
                       fingerprint='orphan',management=False,application_activity=True)}
        self.assertEqual(assess(snapshot(rows=rows),snapshot(100.02,rows),100.04,'boot').state,'busy')
    def test_management_only(self):
        rows={123:dict(start_ticks=20,instances=(),stable=True,container=None,
                       fingerprint='systemd',management=True,application_activity=False)}
        result=assess(snapshot(rows=rows),snapshot(100.02,rows),100.04,'boot')
        self.assertEqual(result.state,'clear'); self.assertFalse(result.selected_active)
    def test_fail_closed_faults(self):
        changes=[dict(errors=['EACCES']),dict(inventory_ok=False),dict(boot='old'),dict(unmapped_containers=True),
                 dict(relevant_pids=(123,456)),dict(container_pids=()),dict(start=float('nan')),
                 dict(end=90),dict(end=101),dict(rows={})]
        for change in changes:
            with self.subTest(change=change):
                self.assertEqual(assess({**snapshot(),**change},snapshot(100.02),100.04,'boot').state,'unknown')
    def test_process_changes(self):
        for change in [dict(start_ticks=999),dict(stable=False),dict(instances=()),dict(fingerprint='replaced')]:
            a,b=snapshot(),snapshot(100.02); b['rows'][123].update(change)
            with self.subTest(change=change): self.assertEqual(assess(a,b,100.04,'boot').state,'unknown')
    def test_stale_and_reboot(self):
        self.assertEqual(assess(snapshot(),snapshot(100.02),103,'boot').state,'unknown')
        self.assertEqual(assess(snapshot(),snapshot(100.02),100.04,'newboot').state,'unknown')
    def test_malformed(self): self.assertEqual(assess({},None,100,'boot').state,'unknown')


class BrokerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.clock=Clock(); self.store=Store(self.temp.name,clock=self.clock)
        self.backend=Backend(); self.verdict=Verdict('clear','observed',True,False,0,'0'*32)
        async def observe(): return self.verdict
        self.broker=Broker(self.backend,observe,self.store,lambda:True,self.clock); self.id=str(uuid.uuid4())
    async def asyncTearDown(self): self.store.close(); self.temp.cleanup()
    async def test_application_once(self):
        await self.broker.start(self.id,OWNER); await self.broker.start(self.id,OWNER)
        self.assertEqual(self.backend.calls.count('application'),1)
    async def test_child_autostart_once(self):
        self.backend.controller=False; self.backend.state='controller_stopped'
        await self.broker.start(self.id,OWNER)
        self.assertEqual(self.backend.calls,['status','child'])
    async def test_busy_unknown_and_orphan(self):
        for verdict in [Verdict('busy','other_activity',True),Verdict(),Verdict('clear','observed',True,True)]:
            self.verdict=verdict
            with self.subTest(verdict=verdict),self.assertRaises(Fault): await self.broker.start(str(uuid.uuid4()),OWNER)
            self.clock.value+=61
        self.assertNotIn('application',self.backend.calls)
    async def test_idempotent_running(self):
        self.backend.state='ready'
        self.assertEqual((await self.broker.start(self.id,OWNER))['code'],'already_running')
        self.assertEqual(self.backend.calls,['status'])
    async def test_disabled_by_default(self):
        self.broker.enabled=lambda:False
        with self.assertRaises(Fault): await self.broker.start(self.id,OWNER)
        self.assertEqual(self.backend.calls,[])
    async def test_failure_after_effect_not_replayed(self):
        async def ambiguous(permit_send): permit_send(); self.backend.calls.append('application'); raise Fault('amp_unavailable')
        self.backend.start_application=ambiguous
        with self.assertRaises(Fault): await self.broker.start(self.id,OWNER)
        self.assertTrue(self.store.unresolved())
        await self.broker.start(self.id,OWNER)
        self.clock.value+=61
        with self.assertRaises(Fault): await self.broker.start(str(uuid.uuid4()),OWNER)
        self.assertEqual(self.backend.calls.count('application'),1)
    async def test_crash_reconcile_read_only(self):
        self.store.create(self.id,'start',OWNER); self.store.update(self.id,'attempted','starting','child')
        await self.broker.reconcile()
        self.assertEqual(self.backend.calls,['status']); self.assertTrue(self.store.unresolved())
    async def test_audit_failure_prevents_effect(self):
        with patch.object(self.store,'update',side_effect=Fault('audit_unavailable')):
            with self.assertRaises(Fault): await self.broker.start(self.id,OWNER)
        self.assertNotIn('application',self.backend.calls)
    async def test_durable_marker_precedes_api(self):
        async def mutate(permit_send):
            permit_send()
            self.assertEqual(self.store.get(self.id)['stage'],'application')
            self.assertEqual(self.store.get(self.id)['state'],'attempted')
        self.backend.start_application=mutate
        await self.broker.start(self.id,OWNER)

    async def test_expired_guard_at_http_boundary_prevents_effect(self):
        async def delayed(permit_send):
            self.clock.value+=3
            permit_send()
            self.backend.calls.append('application')
        self.backend.start_application=delayed
        with self.assertRaises(Fault): await self.broker.start(self.id,OWNER)
        self.assertNotIn('application',self.backend.calls)

    async def test_disable_between_audit_and_send_prevents_effect(self):
        async def delayed(permit_send):
            self.broker.enabled=lambda:False
            permit_send()
            self.backend.calls.append('application')
        self.backend.start_application=delayed
        with self.assertRaises(Fault): await self.broker.start(self.id,OWNER)
        self.assertNotIn('application',self.backend.calls)

    async def test_audit_failure_after_effect_blocks_new_job(self):
        original = self.store.update
        def interrupted(identity,state,code,stage=None):
            if state in {'complete','unknown'}:
                raise Fault('audit_unavailable')
            return original(identity,state,code,stage)
        with patch.object(self.store,'update',interrupted),self.assertRaises(Fault):
            await self.broker.start(self.id,OWNER)
        self.assertEqual(self.backend.calls.count('application'),1)
        self.assertTrue(self.store.unresolved())
        self.clock.value+=61
        with self.assertRaises(Fault): await self.broker.start(str(uuid.uuid4()),OWNER)
        self.assertEqual(self.backend.calls.count('application'),1)


class ControllerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.clock=Clock(); self.store=Store(self.temp.name,clock=self.clock)
        self.effects=[]; self.backend=Backend('ready')
        async def wake(): self.effects.append('wake'); self.backend.error=None
        async def query(): self.effects.append('query'); return True
        async def start(identity,user): self.effects.append('start'); self.backend.state='ready'
        self.backend.start=start
        self.control=Controller(self.store,self.backend,wake,query,lambda:True,self.clock,self.clock.sleep)
    async def asyncTearDown(self):
        for task in tuple(self.control.tasks): task.cancel()
        await asyncio.gather(*self.control.tasks,return_exceptions=True)
        self.store.close(); self.temp.cleanup()
    async def drain(self): await asyncio.gather(*tuple(self.control.tasks))
    async def test_status_never_wakes(self):
        self.backend.error='broker_unavailable'
        result=await self.control.submit(request('status','gameserver'))
        self.assertEqual(result['code'],'broker_unavailable'); self.assertEqual(self.effects,[])
    async def test_denied_never_contacts_host(self):
        with self.assertRaises(Fault): await self.control.submit(request(user='123456789123456789'))
        self.assertEqual(self.backend.calls,[])
    async def test_start_ready_is_read_only(self):
        await self.control.submit(request()); await self.drain()
        self.assertEqual(self.effects,['query']); self.assertEqual(self.store.get(request().id)['code'],'ready')
    async def test_wake_waits_for_amp_without_start(self):
        self.backend.error='broker_unavailable'
        await self.control.submit(request('wake','gameserver')); await self.drain()
        self.assertEqual(self.effects,['wake']); self.assertEqual(self.store.get(request('wake','gameserver').id)['code'],'amp_available')
    async def test_start_wakes_then_starts_once(self):
        self.backend.error='broker_unavailable'; self.backend.state='stopped'
        await self.control.submit(request()); await self.drain()
        self.assertEqual(self.effects,['wake','start','query'])
    async def test_auth_failure_does_not_wake(self):
        self.backend.error='amp_authentication_failed'
        await self.control.submit(request()); await self.drain()
        self.assertEqual(self.effects,[])
    async def test_coalescing(self):
        a=await self.control.submit(request()); b=await self.control.submit(request(number=1))
        self.assertEqual(a['job'],b['job']); await self.drain()
        self.assertEqual(self.effects,['query'])
    async def test_start_not_swallowed_by_wake(self):
        await self.control.submit(request('wake','gameserver'))
        with self.assertRaises(Fault): await self.control.submit(request(number=1))
        await self.drain()
    async def test_status_cooldown(self):
        await self.control.submit(request('status','gameserver'))
        with self.assertRaises(Fault): await self.control.submit(request('status','gameserver',1))
    async def test_recovery_never_wakes_or_starts(self):
        req=request(); self.store.create(req.id,'start',OWNER); self.store.update(req.id,'attempted','starting','wake')
        self.backend.error='broker_unavailable'; await self.control.recover()
        self.assertEqual(self.effects,[]); self.assertTrue(self.store.unresolved())
    async def test_start_deadline_includes_start_request(self):
        self.backend.state='stopped'
        async def slow_start(identity,user): self.clock.value+=601; self.effects.append('start')
        self.backend.start=slow_start
        await self.control.submit(request()); await self.drain()
        self.assertEqual(self.store.get(request().id)['code'],'deadline'); self.assertNotIn('query',self.effects)
    async def test_ready_requires_query(self):
        async def no_query(): return False
        self.control.query=no_query
        await self.control.submit(request()); await self.drain()
        self.assertEqual(self.store.get(request().id)['code'],'deadline')


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_login_body_session_is_retained(self):
        client=Session('', 'unused-test-value')
        with patch.object(client,'call',return_value={'success':True,'sessionID':'test-session'}):
            client.login()
        self.assertEqual(client.token,'test-session')

    async def test_read_refresh_does_not_retry_mutation(self):
        client=Session('', 'unused-test-value'); client.token='expired'
        with patch.object(client,'call',side_effect=[Fault('amp_authentication_failed'),
                           {'success':True,'sessionID':'fresh'}, []]) as calls:
            self.assertEqual(client.read('ADSModule','GetInstanceStatuses'),[])
            self.assertEqual(calls.call_count,3)
        with self.assertRaises(Fault): client.read('Core','Start')

    async def test_no_generic_amp_route(self):
        client=Session('', 'unused-test-value')
        for module,method,body in [('Core','Stop',{}),('ADSModule','GetInstance',{}),('ADSModule','StartInstance',{'InstanceName':'ZomboidLAN01'}),('Core','Start',{})]:
            with self.subTest(method=method),self.assertRaises(Fault): client.call(module,method,body)
    async def test_unknown_summary_not_stopped(self):
        amp=AMP('unused-test-value'); amp.ads.token='test-token'
        with patch.object(amp.ads,'call',return_value=[]),self.assertRaises(Fault): await amp.status()
    async def test_observer_ipc_failure_is_unknown(self):
        with patch('discord_amp.services.rpc',side_effect=Fault('broker_unavailable')):
            self.assertEqual((await observer_call('unused')).state,'unknown')
    async def test_observer_rejects_raw_metadata(self):
        async def value(*args,**kwargs): return {**Verdict('clear','observed',True).public(),'password':'do-not-output'}
        with patch('discord_amp.services.rpc',value):
            self.assertEqual((await observer_call('unused')).state,'unknown')
    async def test_http_auth_and_fixed_routes(self):
        class FakeBroker:
            async def status(self): return {'amp_available':True,'controller':True,'state':'ready'}
            async def start(self,*args): raise AssertionError('must not mutate')
        server=await broker_http(FakeBroker(),'test-token',port=0)
        port=server.sockets[0].getsockname()[1]
        try:
            for path,token,expected in [('/v1/status','test-token',b'200 OK'),('/v1/start/../../API/Core/Stop','test-token',b'400 Bad Request'),('/v1/status','wrong-token',b'400 Bad Request')]:
                reader,writer=await asyncio.open_connection('127.0.0.1',port)
                writer.write(f'POST {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\nX-Profile-SHA256: {profile_fixture.PROFILE.fingerprint}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}'.encode()); await writer.drain()
                data=await reader.read(); writer.close(); await writer.wait_closed()
                self.assertIn(expected,data); self.assertNotIn(b'test-token',data)
        finally: server.close(); await server.wait_closed()
    async def test_a2s_identity(self):
        packet=b'\xff\xff\xff\xffI\x11Synthetic Game\x00\x00Enshrouded\x00Enshrouded\x00'+bytes(10)
        self.assertTrue(parse_a2s(packet)); self.assertFalse(parse_a2s(packet.replace(b'Enshrouded',b'Other Game')))
        self.assertFalse(parse_a2s(packet[:10]))


if __name__=='__main__': unittest.main()
