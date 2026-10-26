"""Configuration and actual consumer composition; all identities are synthetic."""
import asyncio
from copy import deepcopy
import dataclasses
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import profile_fixture as fixture
from discord_amp.config import ConfigError, bind_store, configure, decode, load, parse
from discord_amp import amp, diagnostics, network, wire
from discord_amp.model import Fault, Request
from discord_amp.services import broker_http


class ConfigurationTests(unittest.TestCase):
    def test_strict_profile_and_immutable_inventory(self):
        p = parse(deepcopy(fixture.RAW))
        self.assertEqual(p.selected_id, fixture.INSTANCE_ID)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            p.host = 'changed'
        with self.assertRaises(TypeError):
            p.instances['new'] = ('untrusted', '/')

    def test_malformed_duplicate_unknown_and_secrets_refused(self):
        for raw in (b'{}', b'{"schema":1,"schema":1}', b'[]', b'{"schema":NaN}', b'x' * 65537):
            with self.subTest(raw=raw[:35]), self.assertRaises(ConfigError):
                decode(raw)
        for update in ({'token': 'never a profile field'}, {'schema': True}):
            with self.subTest(update=update), self.assertRaises(ConfigError):
                parse({**deepcopy(fixture.RAW), **update})

    def test_endpoint_injection_paths_ports_and_incomplete_inventory_refuse(self):
        cases = []
        for origin in ('http://example.invalid:8080', 'http://user:pass@127.0.0.1:8080',
                       'http://127.0.0.1:8080/path', 'http://127.0.0.1:8080?x=y'):
            x = deepcopy(fixture.RAW); x['amp']['origin'] = origin; cases.append(x)
        for port in (True, 0, '18081', 65536):
            x = deepcopy(fixture.RAW); x['broker']['port'] = port; cases.append(x)
        for field, value in (('name', 'x\nExecStart=bad'), ('ipv4', '127.0.0.1'), ('mac', 'ff:ff:ff:ff:ff:ff')):
            x = deepcopy(fixture.RAW); x['host'][field] = value; cases.append(x)
        x = deepcopy(fixture.RAW); x['amp']['instances'] = x['amp']['instances'][:1]; cases.append(x)
        x = deepcopy(fixture.RAW); x['amp']['instances'][1]['path'] = '/tmp/../escape'; cases.append(x)
        x = deepcopy(fixture.RAW); x['amp']['instances'][1]['path'] = x['amp']['instances'][0]['path'] + '/nested'; cases.append(x)
        x = deepcopy(fixture.RAW); x['amp']['instances'][1]['id'] = '22222222-1111-4111-8111-111111111111'; cases.append(x)
        for x in cases:
            with self.subTest(case=x), self.assertRaises(ConfigError):
                parse(x)

    def test_profile_cannot_change_under_existing_process(self):
        changed = deepcopy(fixture.RAW); changed['host']['name'] = 'another-host'
        with self.assertRaises(ConfigError):
            configure(parse(changed))
        self.assertIs(configure(fixture.PROFILE), fixture.PROFILE)

    def test_readonly_file_validation_and_no_journal_adoption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root / 'profile.json'
            path.write_text(json.dumps(fixture.RAW), encoding='utf-8')
            self.assertEqual(load(path).fingerprint, fixture.PROFILE.fingerprint)
            (root / 'existing-journal.sqlite').write_bytes(b'old state')
            with self.assertRaises(ConfigError):
                bind_store(root)
            self.assertFalse((root / 'profile.sha256').exists())

    def test_peer_envelope_rejects_foreign_profile_before_handler(self):
        self.assertEqual(wire.unpack(wire.envelope({'operation': 'observe'})), {'operation': 'observe'})
        for value in ({'operation': 'observe'}, {'profile': '0' * 64, 'message': {}},
                      {'profile': fixture.PROFILE.fingerprint, 'message': {}, 'extra': True}):
            with self.subTest(value=value), self.assertRaises(Fault):
                wire.unpack(value)

    def test_wake_packet_only_to_configured_broadcast_without_process_helper(self):
        fake = MagicMock(); sock = fake.return_value.__enter__.return_value
        sock.sendto.return_value = 102
        with patch.object(network.socket, 'socket', fake):
            network.wake_sync()
        payload, destination = sock.sendto.call_args.args
        self.assertEqual(payload, b'\xff' * 6 + bytes.fromhex(fixture.PROFILE.mac.replace(':', '')) * 16)
        self.assertEqual(destination, (fixture.PROFILE.broadcast, 9))
        sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def test_amp_session_origin_selected_child_and_inventory_are_configured(self):
        session = amp.Session(fixture.PROFILE.child_route, 'fixture-only-password')
        self.assertEqual(session.base, fixture.PROFILE.amp_origin + fixture.PROFILE.child_route)
        with self.assertRaises(Fault):
            amp.Session('/API/ADSModule/Servers/ffffffff', 'fixture-only-password')

    def test_render_is_inactive_finite_and_no_private_ip_or_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'units'
            names = diagnostics.render(fixture.PROFILE, output)
            self.assertEqual(len(names), 6)
            for path in output.iterdir():
                value = path.read_text()
                self.assertNotIn('@@', value)
                self.assertNotIn('192.168.', value)
            self.assertIn(fixture.PROFILE.ipv4, (output / 'discord-amp-tunnel.service').read_text())
            with self.assertRaises(ConfigError):
                diagnostics.render(fixture.PROFILE, output)

    def test_doctor_never_reads_credentials_or_network(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('credential read')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network')):
            result = diagnostics.doctor(fixture.PROFILE)
        self.assertFalse(result['credentials_read'])
        self.assertEqual((result['network_probes'], result['mutations']), (0, 0))

    def test_second_installation_drives_actual_policy_amp_and_bot_choices(self):
        root = Path(__file__).resolve().parents[1]
        code = '''import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from discord_amp.config import parse,configure
x=json.loads(Path(sys.argv[2]).read_bytes())
x['host']['name']='another-host'
x['host']['ipv4']='198.51.100.20'
x['host']['broadcast']='198.51.100.255'
x['discord']['application']='200000000000000004'
x['amp']['origin']='http://198.51.100.20:8081'
p=configure(parse(x))
from discord_amp.model import Request,Fault
r=Request('100000000000000010',p.owner,p.guild,p.channel,p.application,(), 'wake',p.host)
r.authorize()
try:
 Request('100000000000000011',p.owner,p.guild,p.channel,p.application,(), 'wake','gameserver').authorize()
 raise AssertionError('private fallback')
except Fault: pass
from discord_amp.amp import AMP
a=AMP('synthetic-password'); assert a.ads.base==p.amp_origin
try:
 import discord
except ImportError:
 print(json.dumps({'policy_amp':True,'bot_checked':False}))
else:
 from discord_amp.bot import build_client
 c=build_client('fixture-only-token','unused.sock',1)
 command=c.tree.get_command('server',guild=discord.Object(id=int(p.guild))).get_command('wake')
 assert [x.value for x in command.parameters[0].choices]==['another-host']
 import asyncio; asyncio.run(c.close())
 print(json.dumps({'policy_amp':True,'bot_checked':True}))
'''
        run = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(root / 'src'),
                              str(root / 'examples/profile.example.json')], capture_output=True, text=True, timeout=15)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(run.stdout)['policy_amp'])


class ProfileHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def test_foreign_profile_never_reaches_broker(self):
        backend = MagicMock()
        server = await broker_http(backend, 'synthetic-broker-token', port=0)
        try:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.write(b'POST /v1/status HTTP/1.1\r\nAuthorization: Bearer synthetic-broker-token\r\n'
                         b'X-Profile-SHA256: wrong\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}')
            await writer.drain()
            response = await reader.read()
            self.assertIn(b'400 Bad Request', response)
            backend.status.assert_not_called()
            backend.start.assert_not_called()
            writer.close(); await writer.wait_closed()
        finally:
            server.close(); await server.wait_closed()
