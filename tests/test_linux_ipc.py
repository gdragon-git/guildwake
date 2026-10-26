import profile_fixture
"""Native Linux-only socket checks; fake handlers never touch AMP or WOL."""
import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest
from discord_amp.model import Fault
from discord_amp.wire import serve_unix, rpc


@unittest.skipUnless(sys.platform == 'linux', 'Linux SO_PEERCRED required')
class LinuxIPCTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='discord-amp-ipc-')
        self.path = str(Path(self.tmp.name) / 'test.sock')
        self.servers = []
        self.loop = asyncio.get_running_loop()
        self.errors = []
        self.previous_handler = self.loop.get_exception_handler()
        self.loop.set_exception_handler(lambda loop, context: self.errors.append(context.get('message', 'callback_error')))
    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()
            await asyncio.sleep(0)
            await asyncio.gather(*tuple(server.client_tasks))
        self.tmp.cleanup()
        self.loop.set_exception_handler(self.previous_handler)
        self.assertEqual(self.errors, [])
    async def open(self, uid):
        async def handler(message):
            if message != {'operation': 'observe'}:
                raise Fault('unsupported_command')
            return {'state': 'unknown'}
        self.servers.append(await serve_unix(self.path, uid, handler))
    async def test_actual_peer_identity_both_directions(self):
        await self.open(os.geteuid())
        self.assertEqual(await rpc(self.path, {'operation':'observe'}, os.geteuid()), {'state':'unknown'})
        self.assertEqual(Path(self.path).stat().st_mode & 0o777, 0o660)
    async def test_wrong_caller_refused(self):
        await self.open(os.geteuid() + 1)
        with self.assertRaises(Fault) as error:
            await rpc(self.path, {'operation':'observe'}, os.geteuid())
        self.assertEqual(error.exception.code, 'not_authorized')
    async def test_wrong_server_refused(self):
        await self.open(os.geteuid())
        with self.assertRaises(Fault):
            await rpc(self.path, {'operation':'observe'}, os.geteuid() + 1)
    async def test_no_existing_socket_unlink(self):
        await self.open(os.geteuid())
        with self.assertRaises(Fault):
            await self.open(os.geteuid())
    async def test_unknown_operation_cannot_select_paths(self):
        await self.open(os.geteuid())
        with self.assertRaises(Fault):
            await rpc(self.path, {'operation':'observe','path':'/etc/shadow'}, os.geteuid())
