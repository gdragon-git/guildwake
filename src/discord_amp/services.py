"""Loopback broker HTTP boundary and fixed controller/observer RPC handlers."""
import asyncio
import hmac
import json
import re
import time
from .guard import Verdict
from .model import decode, Fault, StartBlocked, Request, STATES
from .wire import close_writer, http_request, rpc
from .config import current


class BrokerClient:
    def __init__(self, path, token):
        self.path, self.token = path, token

    async def status(self):
        value = await http_request(self.path, self.token, '/v1/status', {})
        if (set(value) != {'amp_available', 'controller', 'state'} or value['amp_available'] is not True
                or type(value['controller']) is not bool or value['state'] not in STATES):
            raise Fault('broker_rejected')
        return value

    async def start(self, identity, user):
        value = await http_request(self.path, self.token, '/v1/start', {'id': identity, 'user': user, 'at': time.time()})
        if value.get('state') == 'blocked':
            raise StartBlocked.parse(value, identity, user)
        if set(value) != {'id', 'code'} or value['id'] != identity or value['code'] not in {'starting', 'already_running'}:
            raise Fault('broker_rejected')
        return value


async def observer_call(path, uid=0):
    # Measure complete IPC age as well as host acquisition age. The observer
    # computes on demand; no cached permissive result is accepted on reconnect.
    began = time.monotonic()
    try:
        value = await rpc(path, {'operation': 'observe'}, uid, timeout=2)
        if set(value) != {'state', 'reason', 'covered', 'selected_active', 'age_ms', 'generation'}:
            return Verdict()
        if (value['state'] not in {'clear', 'busy', 'unknown'}
                or value['reason'] not in {'observed', 'other_activity', 'amp_maintenance', 'observation_failed', 'stale_observation',
                                          'coverage_mismatch', 'unclassified_process', 'observation_changed'}
                or type(value['covered']) is not bool or type(value['selected_active']) is not bool
                or time.monotonic() - began > 2):
            return Verdict()
        if value['reason'] == 'amp_maintenance' and (value['state'] != 'busy' or value['covered'] is not True):
            return Verdict()
        if value['state'] != 'unknown' and (type(value['age_ms']) is not int or not 0 <= value['age_ms'] <= 2000
                or not isinstance(value['generation'], str) or not re.fullmatch('[0-9a-f]{32}', value['generation'])):
            return Verdict()
        return Verdict(**value)
    except Fault:
        return Verdict()


async def observer_handler(collector, message):
    if message != {'operation': 'observe'}:
        raise Fault('unsupported_command')
    return (await asyncio.to_thread(collector.verdict)).public()


async def controller_handler(controller, message):
    if set(message) not in ({'operation', 'request'}, {'operation', 'request', 'job'}):
        raise Fault('invalid_request')
    request = Request.parse(message['request'])
    if message['operation'] == 'submit' and set(message) == {'operation', 'request'}:
        return await controller.submit(request)
    if message['operation'] == 'progress' and set(message) == {'operation', 'request', 'job'}:
        return await controller.progress(request, message['job'])
    raise Fault('unsupported_command')


async def broker_http(broker, token, host='127.0.0.1', port=18081):
    slots = asyncio.Semaphore(8)
    async def connection(reader, writer):
        ok = True
        try:
            async with asyncio.timeout(30), slots:
                head = await reader.readuntil(b'\r\n\r\n')
                if len(head) > 4096:
                    raise Fault('invalid_request')
                lines = head.decode('ascii').split('\r\n')
                method, path, version = lines[0].split(' ')
                if method != 'POST' or version != 'HTTP/1.1' or path not in {'/v1/status', '/v1/start'}:
                    raise Fault('unsupported_command')
                headers = {}
                for line in lines[1:]:
                    if not line:
                        continue
                    name, value = line.split(':', 1)
                    name = name.lower()
                    if name in headers:
                        raise Fault('invalid_request')
                    headers[name] = value.strip()
                if not hmac.compare_digest(headers.get('authorization', ''), 'Bearer ' + token):
                    raise Fault('not_authorized')
                if not hmac.compare_digest(headers.get('x-profile-sha256', ''), current().fingerprint):
                    raise Fault('not_authorized')
                if ('transfer-encoding' in headers or not headers.get('content-length', '').isdigit()
                        or int(headers['content-length']) > 4096 or headers.get('content-type') != 'application/json'):
                    raise Fault('invalid_request')
                body = decode(await reader.readexactly(int(headers['content-length'])))
                if path == '/v1/status' and body == {}:
                    value = await broker.status()
                elif (path == '/v1/start' and set(body) == {'id', 'user', 'at'}
                      and type(body['at']) in {int, float} and abs(time.time() - body['at']) <= 60):
                    value = await broker.start(body['id'], body['user'])
                else:
                    raise Fault('invalid_request')
        except Exception as exc:
            ok = False
            value = exc.public() if isinstance(exc, StartBlocked) else {'error': exc.code if isinstance(exc, Fault) else 'request_failed'}
        try:
            raw = json.dumps(value, separators=(',', ':')).encode()
            # Authenticated structured error codes share 200 framing; secrets or
            # API error text are never included. Malformed/unauthenticated input
            # receives only a generic HTTP failure and a closed connection.
            status = '400 Bad Request' if not ok and value.get('error') in {'not_authorized', 'invalid_request', 'unsupported_command'} else '200 OK'
            writer.write(f'HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n'.encode() + raw)
            await writer.drain()
        except OSError:
            pass
        finally:
            await close_writer(writer)
    return await asyncio.start_server(connection, host, port, limit=8192)
