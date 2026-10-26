"""Offline validation, metadata-only diagnostics and inactive service rendering."""
import json
import os
from pathlib import Path
import stat
import sys
from .config import ConfigError, load


def render(profile, directory):
    # This creates ordinary local text files, never installs/reloads a unit.
    if directory.exists():
        raise ConfigError('output_exists')
    directory.mkdir(parents=True)
    replacements = {'@@HOST_IPV4@@': profile.ipv4, '@@BROADCAST@@': profile.broadcast,
                    '@@HOST@@': profile.host, '@@BROKER_PORT@@': str(profile.broker_port)}
    names = []
    for template in sorted((Path(__file__).parent / 'templates').iterdir()):
        if not template.is_file():
            continue
        text = template.read_text(encoding='utf-8')
        for old, new in replacements.items():
            text = text.replace(old, new)
        if '@@' in text:
            raise ConfigError('template_invalid')
        (directory / template.name).write_text(text, encoding='utf-8', newline='\n')
        names.append(template.name)
    return names


def doctor(profile):
    names = ('discord-amp-bot', 'discord-amp-controller', 'discord-amp-broker', 'discord-amp-tunnel', profile.amp_user)
    users = {}
    if sys.platform == 'linux':
        import pwd
        for name in names:
            try:
                pwd.getpwnam(name)
                users[name] = 'present'
            except KeyError:
                users[name] = 'missing'
    # Inspect credential source metadata only. Never read contents or a token.
    credential_sources = {}
    for role, entries in {'bot': ('discord-token',), 'controller': ('broker-token',),
                          'broker': ('broker-token', 'amp-password'), 'tunnel': ('tunnel-key',)}.items():
        for entry in entries:
            path = Path('/etc/discord-amp-' + role + '/credentials') / entry
            key = role + '/' + entry
            try:
                info = path.lstat()
                credential_sources[key] = 'protected' if (stat.S_ISREG(info.st_mode)
                    and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o400) else 'unsafe'
            except OSError:
                credential_sources[key] = 'unavailable'
    gates = {}
    for role in ('controller', 'broker'):
        try:
            info = Path('/etc/discord-amp-' + role + '/enable-mutations').lstat()
            gates[role] = 'enabled' if (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                                       and not info.st_mode & 0o022) else 'unsafe'
        except OSError:
            gates[role] = 'absent-or-unreadable'
    return {'configuration_valid': True, 'profile_sha256': profile.fingerprint,
            'platform': sys.platform, 'linux_service_prerequisites_checked': sys.platform == 'linux',
            'users': users, 'credential_source_metadata': credential_sources,
            'mutation_gate_metadata': gates,
            'credentials_read': False, 'network_probes': 0, 'mutations': 0,
            'installation_qualified': False}


def local_command(args, parser):
    try:
        profile = load(Path(args.config))
        if args.role == 'render':
            if not args.output:
                raise ConfigError('output_required')
            result = {'files': render(profile, Path(args.output)), 'installed': False, 'services_started': False}
        elif args.role == 'doctor':
            result = doctor(profile)
        else:
            result = {'configuration_valid': True, 'profile_sha256': profile.fingerprint,
                      'secrets_read': False, 'network_probes': 0, 'mutations': 0}
        print(json.dumps(result, sort_keys=True))
    except (ConfigError, OSError) as exc:
        parser.exit(2, (exc.code if isinstance(exc, ConfigError) else 'local_output_failed') + '\n')
