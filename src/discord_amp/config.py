"""Explicit, immutable installation policy. No import-time IO or private defaults."""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from urllib.parse import urlsplit
import uuid


class ConfigError(ValueError):
    def __init__(self, code='configuration_invalid'):
        self.code = code
        super().__init__(code)


def keys(value, expected):
    if type(value) is not dict or set(value) != set(expected.split()):
        raise ConfigError()


def text(value, pattern, limit=256):
    if not isinstance(value, str) or len(value) > limit or not re.fullmatch(pattern, value):
        raise ConfigError()
    return value


def absolute(value):
    text(value, r'/[A-Za-z0-9_./-]+', 1024)
    if '..' in value.split('/') or '//' in value or value == '/' or value.endswith('/'):
        raise ConfigError()
    return value


def identifier(value):
    text(value, r'[0-9a-f-]{36}')
    if str(uuid.UUID(value)) != value:
        raise ConfigError()
    return value


def ipv4(value):
    if not isinstance(value, str) or str(ipaddress.IPv4Address(value)) != value:
        raise ConfigError()
    return value


def number(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ConfigError()
    return value


@dataclass(frozen=True)
class Profile:
    application: str
    guild: str
    channel: str
    owner: str
    role: str
    host: str
    ipv4: str
    mac: str
    broadcast: str
    amp_origin: str
    amp_username: str
    selected: str
    management: str
    instances: object
    inventory_path: str
    storage_mount: str
    storage_uuid: str
    amp_user: str
    maintenance_exe: str
    maintenance_alias: str
    maintenance_unit: str
    systemd_exe: str
    amp_binary: str
    query_port: int
    broker_port: int
    fingerprint: str
    game: str = 'enshrouded'

    @property
    def selected_id(self):
        return self.instances[self.selected][0]

    @property
    def child_route(self):
        return '/API/ADSModule/Servers/' + self.selected_id[:8]

    @property
    def commands(self):
        return frozenset({('status', self.host), ('wake', self.host), ('start', self.game)})


def parse(value):
    try:
        keys(value, 'schema discord host amp observer query broker')
        if type(value['schema']) is not int or value['schema'] != 1:
            raise ConfigError()
        d, h, a, o = (value[k] for k in ('discord', 'host', 'amp', 'observer'))
        keys(d, 'application guild channel owner role')
        for field in d.values():
            text(field, r'[1-9][0-9]{16,19}', 20)
        keys(h, 'name ipv4 mac broadcast')
        text(h['name'], r'[a-z][a-z0-9-]{0,31}')
        address, broadcast = ipv4(h['ipv4']), ipv4(h['broadcast'])
        host_ip = ipaddress.IPv4Address(address)
        if host_ip.is_unspecified or host_ip.is_multicast or host_ip.is_loopback or address == '255.255.255.255':
            raise ConfigError()
        if ipaddress.IPv4Address(broadcast).is_multicast or ipaddress.IPv4Address(broadcast).is_unspecified:
            raise ConfigError()
        text(h['mac'], r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', 17)
        octets = bytes.fromhex(h['mac'].replace(':', ''))
        if octets == bytes(6) or octets[0] & 1:
            raise ConfigError()
        keys(a, 'origin username selected management inventory instances')
        origin = urlsplit(a['origin'])
        if (origin.scheme not in {'http', 'https'} or origin.hostname not in {'127.0.0.1', address}
                or origin.username or origin.password or origin.path or origin.query or origin.fragment
                or origin.port is None or a['origin'] != f'{origin.scheme}://{origin.hostname}:{origin.port}'):
            raise ConfigError()
        number(origin.port, 1, 65535)
        text(a['username'], r'[A-Za-z0-9_.-]{1,64}')
        for key in ('selected', 'management'):
            text(a[key], r'[A-Za-z][A-Za-z0-9_-]{0,63}')
        absolute(a['inventory'])
        if type(a['instances']) is not list or not 2 <= len(a['instances']) <= 32:
            raise ConfigError()
        instances = {}
        for row in a['instances']:
            keys(row, 'name id path')
            name = text(row['name'], r'[A-Za-z][A-Za-z0-9_-]{0,63}')
            if name in instances:
                raise ConfigError()
            instances[name] = (identifier(row['id']), absolute(row['path']))
        ids, paths = zip(*instances.values())
        if (len(set(ids)) != len(ids) or len({item[:8] for item in ids}) != len(ids) or len(set(paths)) != len(paths)
                or a['selected'] not in instances or a['management'] not in instances
                or a['selected'] == a['management']):
            raise ConfigError()
        # Overlapping roots would make ownership ambiguous.
        if any(x != y and PurePosixPath(x).is_relative_to(y) for x in paths for y in paths):
            raise ConfigError()
        keys(o, 'storage_mount storage_uuid amp_user maintenance_exe maintenance_alias maintenance_unit systemd_exe amp_binary')
        for key in ('storage_mount', 'maintenance_exe', 'maintenance_alias', 'maintenance_unit', 'systemd_exe'):
            absolute(o[key])
        identifier(o['storage_uuid'])
        text(o['amp_user'], r'[a-z_][a-z0-9_-]{0,31}')
        if o['amp_binary'] not in {'AMP_Linux_x86_64', 'AMP_Linux_aarch64'}:
            raise ConfigError()
        if not o['maintenance_unit'].endswith('.service'):
            raise ConfigError()
        keys(value['query'], 'port')
        keys(value['broker'], 'port')
        query = number(value['query']['port'], 1024, 65535)
        broker = number(value['broker']['port'], 1024, 65535)
        fingerprint = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return Profile(**d, host=h['name'], ipv4=address, mac=h['mac'], broadcast=broadcast,
            amp_origin=a['origin'], amp_username=a['username'], selected=a['selected'], management=a['management'],
            instances=MappingProxyType(instances), inventory_path=a['inventory'],
            storage_mount=o['storage_mount'], storage_uuid=o['storage_uuid'], amp_user=o['amp_user'],
            maintenance_exe=o['maintenance_exe'], maintenance_alias=o['maintenance_alias'],
            maintenance_unit=o['maintenance_unit'], systemd_exe=o['systemd_exe'], amp_binary=o['amp_binary'],
            query_port=query, broker_port=broker, fingerprint=fingerprint)
    except ConfigError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        raise ConfigError() from None


def decode(raw):
    if type(raw) is not bytes or len(raw) > 65536:
        raise ConfigError()
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ConfigError()
            result[key] = value
        return result
    try:
        return parse(json.loads(raw, object_pairs_hook=pairs,
                                parse_constant=lambda _: (_ for _ in ()).throw(ConfigError())))
    except (ValueError, UnicodeError, RecursionError):
        raise ConfigError() from None


def load(path, protected=False):
    """Read bounded regular file; service policy must be root-owned, nonwritable."""
    try:
        if protected:
            if not path.is_absolute():
                raise ConfigError('configuration_unprotected')
            for parent in path.parents:
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ConfigError('configuration_unprotected')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        if path.is_symlink():
            raise ConfigError('configuration_unprotected')
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > 65536:
                raise ConfigError()
            if protected and (before.st_uid != 0 or before.st_mode & 0o022):
                raise ConfigError('configuration_unprotected')
            raw = stream.read(65537)
            after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ConfigError('configuration_changed')
        return decode(raw)
    except OSError:
        raise ConfigError('configuration_unavailable') from None


_profile = None


def current():
    if _profile is None:
        raise ConfigError('configuration_required')
    return _profile


def configure(profile):
    global _profile
    if not isinstance(profile, Profile):
        raise ConfigError()
    if _profile is not None and _profile.fingerprint != profile.fingerprint:
        raise ConfigError('configuration_already_bound')
    _profile = profile
    return profile


def bind_store(directory):
    """Refuse to reuse an old installation journal under another policy."""
    marker = directory / 'profile.sha256'
    wanted = (current().fingerprint + '\n').encode('ascii')
    if directory.is_symlink() or not directory.is_dir():
        raise ConfigError('journal_unbound')
    info = directory.stat()
    if info.st_uid != getattr(os, 'geteuid', lambda: info.st_uid)() or info.st_mode & 0o022:
        raise ConfigError('journal_unbound')
    if marker.is_symlink():
        raise ConfigError('journal_policy_mismatch')
    if marker.exists():
        fd = os.open(marker, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_size != len(wanted)
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or stream.read(128) != wanted):
                raise ConfigError('journal_policy_mismatch')
    else:
        if any(directory.iterdir()):
            raise ConfigError('journal_unbound')
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(wanted)
            stream.flush()
            os.fsync(stream.fileno())
