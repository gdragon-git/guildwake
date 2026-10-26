import profile_fixture
"""Status timeout/cancellation/recovery: fake host effects, temporary journals."""
import asyncio
from dataclasses import asdict
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from discord_amp import controller as module
from discord_amp.controller import Controller
from discord_amp.model import Request, Fault
from profile_fixture import OWNER, GUILD, CHANNEL, APPLICATION
from discord_amp.services import controller_handler,BrokerClient
from discord_amp.store import Store
from discord_amp.wire import rpc,serve_unix,close_writer

def request(number=1,action='status'):
 return Request(str(900000000000001000+number),OWNER,GUILD,CHANNEL,APPLICATION,(),action,'enshrouded' if action=='start' else 'gameserver')

class Backend:
 def __init__(self): self.mode='stall'; self.entered=asyncio.Event(); self.calls=0
 async def status(self):
  self.calls+=1; self.entered.set()
  if self.mode=='stall': await asyncio.Event().wait()
  if self.mode=='unavailable': raise Fault('broker_unavailable')
  if isinstance(self.mode,Exception): raise self.mode
  if self.mode=='malformed': return {}
  return {'amp_available':True,'controller':True,'state':'ready'}
 async def start(self,*args): raise AssertionError('status must not start')

class StatusRecoveryTests(unittest.IsolatedAsyncioTestCase):
 async def asyncSetUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.store=Store(self.tmp.name)
  self.backend=Backend(); self.effects=[]
  async def wake(): self.effects.append('wake'); self.backend.mode='ready'
  async def query(): self.effects.append('query'); return True
  self.control=Controller(self.store,self.backend,wake,query,lambda:True)
 async def asyncTearDown(self):
  for task in tuple(self.control.tasks): task.cancel()
  await asyncio.gather(*self.control.tasks,return_exceptions=True)
  self.store.close(); self.tmp.cleanup()
 def no_hold(self,identity):
  self.assertEqual(self.store.get(identity)['state'],'failed')
  self.assertFalse(self.store.unresolved()); self.assertEqual(self.effects,[])
 async def explicit_wake(self):
  self.backend.mode='unavailable'
  await self.control.submit(request(99,'wake'))
  await asyncio.gather(*self.control.tasks)
  self.assertEqual(self.effects,['wake'])
  self.assertEqual(self.store.get(request(99,'wake').id)['code'],'amp_available')
 async def test_status_deadline_finishes_before_rpc_and_allows_explicit_wake(self):
  began=time.monotonic()
  with patch.object(module,'STATUS_TIMEOUT',.03): result=await self.control.submit(request())
  self.assertLess(time.monotonic()-began,1)
  self.assertEqual(result['code'],'broker_unavailable'); self.no_hold(request().id)
  await self.explicit_wake()
 async def test_direct_cancellation_persists_then_propagates(self):
  task=asyncio.create_task(self.control.submit(request()))
  await self.backend.entered.wait(); task.cancel()
  with self.assertRaises(asyncio.CancelledError): await task
  self.no_hold(request().id); await self.explicit_wake()
 async def test_deadline_includes_lock_queue_no_job_created(self):
  async with self.control.lock:
   with patch.object(module,'STATUS_TIMEOUT',.03),self.assertRaises(Fault) as error:
    await self.control.submit(request())
  self.assertEqual(error.exception.code,'broker_unavailable')
  self.assertIsNone(self.store.get(request().id)); self.assertEqual(self.backend.calls,0)
 async def test_read_failures_are_terminal_and_sanitized(self):
  for number,mode in enumerate([OSError('private text'),TimeoutError('private text'),RuntimeError('private text'),'malformed',Fault('amp_authentication_failed')],1):
   self.backend.mode=mode; self.control.status_times.clear()
   result=await self.control.submit(request(number))
   self.assertNotIn('private text',str(result)); self.no_hold(request(number).id)
 async def test_durable_failure_keeps_hold_and_latches_refusal(self):
  task=asyncio.create_task(self.control.submit(request())); await self.backend.entered.wait()
  with patch.object(self.store,'update',side_effect=Fault('audit_unavailable')):
   task.cancel()
   with self.assertRaises(Fault) as error: await task
  self.assertEqual(error.exception.code,'audit_unavailable'); self.assertTrue(self.store.unresolved())
  with self.assertRaises(Fault) as error: await self.control.submit(request(99,'wake'))
  self.assertEqual(error.exception.code,'audit_unavailable'); self.assertEqual(self.effects,[])
 async def test_recovery_clears_all_interrupted_and_legacy_unknown_statuses_without_host(self):
  for number,state in enumerate(['accepted','working','attempted','unknown'],1):
   req=request(number); self.store.create(req.id,'status',OWNER)
   if state!='accepted': self.store.update(req.id,state,'unknown')
  # Reopen the real journal to model a new process, not cached in-memory state.
  self.store.close(); self.store=Store(self.tmp.name); self.control.store=self.store
  await self.control.recover()
  self.assertEqual(self.backend.calls,0); self.assertFalse(self.store.unresolved())
  for number in range(1,5):
   job=self.store.get(request(number).id)
   self.assertEqual((job['state'],job['code'],job['stage']),('failed','broker_unavailable','reconcile'))
  await self.explicit_wake()
 async def test_genuine_mutation_holds_preserved_and_never_replayed(self):
  for number,action in [(10,'wake'),(11,'start')]:
   req=request(number,action); self.store.create(req.id,action,OWNER); self.store.update(req.id,'unknown','unknown')
  req=request(12,'start'); self.store.create(req.id,'start',OWNER); self.store.update(req.id,'attempted','starting','application')
  self.backend.mode='unavailable'; await self.control.recover()
  self.assertTrue(self.store.unresolved()); self.assertEqual(self.effects,[])
  for number,action in [(10,'wake'),(11,'start'),(12,'start')]: self.assertEqual(self.store.get(request(number,action).id)['state'],'unknown')
  with self.assertRaises(Fault) as error: await self.control.submit(request(99,'wake'))
  self.assertEqual(error.exception.code,'review_required')
 async def test_mutation_recovery_unavailable_is_bounded(self):
  req=request(12,'start'); self.store.create(req.id,'start',OWNER)
  with patch.object(module,'STATUS_TIMEOUT',.03): await self.control.recover()
  self.assertEqual(self.store.get(req.id)['state'],'unknown'); self.assertEqual(self.effects,[])
 async def test_recovery_audit_failure_does_not_clear_mutation_holds(self):
  self.store.create(request().id,'status',OWNER)
  self.store.create(request(12,'start').id,'start',OWNER)
  with patch.object(self.store,'update',side_effect=Fault('audit_unavailable')),self.assertRaises(Fault): await self.control.recover()
  self.assertTrue(self.store.unresolved()); self.assertEqual(self.backend.calls,0); self.assertEqual(self.effects,[])

@unittest.skipUnless(sys.platform=='linux','Linux AF_UNIX peer identity required')
class NativeStatusTests(StatusRecoveryTests):
 # Inherits the portable cases under Linux as the actual qualification UID.
 async def open_servers(self):
  self.servers=[]; self.loop=asyncio.get_running_loop(); self.errors=[]
  self.old_handler=self.loop.get_exception_handler()
  self.loop.set_exception_handler(lambda loop,ctx:self.errors.append(ctx.get('message','callback_error')))
  self.fake_clients=set()
  async def stalled(reader,writer):
   task=asyncio.current_task(); self.fake_clients.add(task)
   try:
    await reader.readuntil(b'\r\n\r\n'); await reader.readexactly(2)
    # Deliberately never return HTTP headers; wait for client closure.
    await reader.read()
   finally: await close_writer(writer); self.fake_clients.discard(task)
  self.http_path=str(Path(self.tmp.name)/'fake-broker.sock')
  self.servers.append(await asyncio.start_unix_server(stalled,self.http_path))
  self.control.broker=BrokerClient(self.http_path,'dummy-qualification-token')
  self.rpc_path=str(Path(self.tmp.name)/'controller.sock')
  self.servers.append(await serve_unix(self.rpc_path,os.geteuid(),lambda msg:controller_handler(self.control,msg)))
 async def close_servers(self):
  for server in self.servers: server.close(); await server.wait_closed()
  for server in self.servers:
   if hasattr(server,'client_tasks'): await asyncio.gather(*tuple(server.client_tasks))
  if self.fake_clients: await asyncio.wait_for(asyncio.gather(*tuple(self.fake_clients)),2)
  self.loop.set_exception_handler(self.old_handler); self.assertEqual(self.errors,[])
 def message(self):
  obj=asdict(request()); obj['roles']=[]
  return {'operation':'submit','request':obj}
 async def test_real_socket_uses_production_six_second_deadline(self):
  await self.open_servers()
  try:
   began=time.monotonic(); result=await rpc(self.rpc_path,self.message(),os.geteuid())
   elapsed=time.monotonic()-began
   self.assertEqual(module.STATUS_TIMEOUT,6); self.assertGreaterEqual(elapsed,5.5); self.assertLess(elapsed,9)
   self.assertEqual(result['code'],'broker_unavailable'); self.no_hold(request().id)
   self.control.broker=self.backend; await self.explicit_wake()
  finally: await self.close_servers()
 async def test_disconnected_caller_leaves_no_hold(self):
  await self.open_servers()
  try:
   reader,writer=await asyncio.open_unix_connection(self.rpc_path)
   import json
   writer.write(json.dumps(self.message()).encode()+b'\n'); await writer.drain()
   # Ensure the request was accepted before dropping the caller.
   deadline=time.monotonic()+1
   while self.store.get(request().id) is None:
    if time.monotonic()>deadline: self.fail('request not accepted')
    await asyncio.sleep(.01)
   await close_writer(writer)
   with patch.object(module,'STATUS_TIMEOUT',6):
    deadline=time.monotonic()+8
    while self.store.get(request().id)['state']=='accepted':
     if time.monotonic()>deadline: self.fail('disconnected status did not settle')
     await asyncio.sleep(.02)
   self.no_hold(request().id)
   self.control.broker=self.backend; await self.explicit_wake()
  finally: await self.close_servers()
