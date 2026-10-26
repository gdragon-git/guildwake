"""Explicit-request UDP wake and bounded configured Enshrouded query."""
import asyncio
import socket
from .config import current


def wake_sync():
    profile = current()
    packet = b'\xff' * 6 + bytes.fromhex(profile.mac.replace(':', '')) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if sock.sendto(packet, (profile.broadcast, 9)) != len(packet):
            raise OSError('wake_send_failed')


async def wake():
    # Called only by the coordinator's explicit durable mutation path.
    await asyncio.to_thread(wake_sync)


def parse_a2s(body):
    if not body.startswith(b'\xff\xff\xff\xffI') or len(body) < 6:
        return False
    offset, values = 6, []
    try:
        for _ in range(4):
            end = body.index(b'\x00', offset)
            values.append(body[offset:end].decode('utf-8'))
            offset = end + 1
        return values[2] == 'Enshrouded' and len(body) >= offset + 8
    except (ValueError, UnicodeError):
        return False


def query_sync():
    address = (current().ipv4, current().query_port)
    request = b'\xff\xff\xff\xffTSource Engine Query\x00'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.connect(address)
            sock.send(request)
            body = sock.recv(4096)
            if body.startswith(b'\xff\xff\xff\xffA') and len(body) == 9:
                sock.send(request + body[5:])
                body = sock.recv(4096)
            return parse_a2s(body)
    except OSError:
        return False


async def query():
    return await asyncio.to_thread(query_sync)
