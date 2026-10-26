"""Bounded newline JSON IPC; Linux peer credentials authenticate local services."""
import asyncio
import hmac
import json
import os
from pathlib import Path
import socket
import struct
from .model import decode, Fault
from .config import current


def envelope(message):
    return {'profile': current().fingerprint, 'message': message}


def unpack(value):
    if (type(value) is not dict or set(value) != {'profile', 'message'}
            or type(value['profile']) is not str
            or not hmac.compare_digest(value['profile'], current().fingerprint)
            or type(value['message']) is not dict):
        raise Fault('not_authorized')
    return value['message']


def peer_uid(sock):
    if not hasattr(socket, 'SO_PEERCRED'):
        raise Fault('platform_unsupported')
    return struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


async def close_writer(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        # A peer may close immediately after identity rejection. This is an
        # ordinary disconnect, not an unhandled callback/traceback.
        pass


async def rpc(path, message, server_uid, timeout=12):
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_unix_connection(path, limit=8192)
            try:
                if peer_uid(writer.get_extra_info('socket')) != server_uid:
                    raise Fault('not_authorized')
                raw = json.dumps(envelope(message), separators=(',', ':')).encode()
                if len(raw) > 4096:
                    raise Fault('invalid_message')
                writer.write(raw + b'\n')
                await writer.drain()
                response = decode(await reader.readline())
                if set(response) == {'error'}:
                    raise Fault(response['error'])
                return response
            finally:
                await close_writer(writer)
    except (OSError, TimeoutError, ValueError, asyncio.LimitOverrunError):
        raise Fault('broker_unavailable') from None


async def serve_unix(path, allowed_uid, handler, mode=0o660):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise Fault('socket_already_exists')
    # RuntimeDirectory/group/ownership are deployment responsibilities; do not
    # unlink or chmod an existing directory or someone else's endpoint here.
    slots = asyncio.Semaphore(8)
    clients = set()
    async def connection(reader, writer):
        task = asyncio.current_task()
        clients.add(task)
        try:
            async with asyncio.timeout(10), slots:
                if peer_uid(writer.get_extra_info('socket')) != allowed_uid:
                    raise Fault('not_authorized')
                result = await handler(unpack(decode(await reader.readline())))
                raw = json.dumps(result, separators=(',', ':')).encode()
                if len(raw) > 4096:
                    raise Fault('invalid_message')
                writer.write(raw + b'\n')
                await writer.drain()
        except Exception as exc:
            code = exc.code if isinstance(exc, Fault) else 'request_failed'
            writer.write(json.dumps({'error': code}).encode() + b'\n')
            try:
                await writer.drain()
            except OSError:
                pass
        finally:
            await close_writer(writer)
            clients.discard(task)
    server = await asyncio.start_unix_server(connection, str(path), limit=8192)
    server.client_tasks = clients
    os.chmod(path, mode)
    return server


async def http_request(socket_path, token, path, body):
    if path not in {'/v1/status', '/v1/start'}:
        raise Fault('unsupported_command')
    try:
        async with asyncio.timeout(30):
            reader, writer = await asyncio.open_unix_connection(socket_path, limit=8192)
            try:
                raw = json.dumps(body).encode()
                writer.write((f'POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nX-Profile-SHA256: {current().fingerprint}\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n').encode() + raw)
                await writer.drain()
                headers = await reader.readuntil(b'\r\n\r\n')
                lines = headers.decode('ascii').split('\r\n')
                if lines[0] != 'HTTP/1.1 200 OK':
                    raise Fault('broker_rejected')
                lengths = [line[16:].strip() for line in lines[1:] if line.lower().startswith('content-length: ')]
                if len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) > 4096:
                    raise Fault('invalid_message')
                result = decode(await reader.readexactly(int(lengths[0])))
                if set(result) == {'error'}:
                    raise Fault(result['error'])
                return result
            finally:
                await close_writer(writer)
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        raise Fault('broker_unavailable') from None
