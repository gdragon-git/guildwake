"""Explicit Linux service entry points. No installation, wake or start on import."""
import argparse
import asyncio
from functools import partial
import os
from pathlib import Path
import stat
import sys
from .model import Fault, job_id
from .config import current, load, configure, ConfigError, bind_store


def credential(name):
    if name not in {'discord-token', 'broker-token', 'amp-password'}:
        raise Fault('invalid_request')
    path = Path(os.environ['CREDENTIALS_DIRECTORY']) / name
    st = path.stat()
    # systemd 257 may expose its private read-only copy as root:root 0440,
    # granting this unit's UID read access via ACL. The root-group read mask
    # is not access for another application group. Keep source files 0400;
    # never chmod credential copies or loosen their directory/namespace.
    mode = stat.S_IMODE(st.st_mode)
    private_mode = mode == 0o400 or (mode == 0o440 and st.st_uid == 0 and st.st_gid == 0)
    if (st.st_uid not in {0, os.geteuid()} or not stat.S_ISREG(st.st_mode)
            or not private_mode or path.is_symlink()):
        raise Fault('credential_unavailable')
    raw = path.read_bytes()
    if not 1 <= len(raw) <= 4096:
        raise Fault('credential_unavailable')
    value = raw.decode('utf-8')
    # Preserve the owner's AMP password exactly; do not strip whitespace or add
    # a password-length policy. Tokens must be suitable for a single header.
    if name != 'amp-password' and (len(value) < 32 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in value)):
        raise Fault('credential_unavailable')
    return value


def enabled(role):
    path = Path('/etc/discord-amp-' + role + '/enable-mutations')
    try:
        st = path.lstat()
        return path.is_file() and not path.is_symlink() and st.st_uid == 0 and not st.st_mode & 0o022
    except OSError:
        return False


async def service(role):
    import pwd
    from .wire import serve_unix
    from .services import BrokerClient, broker_http, controller_handler, observer_handler, observer_call
    from .store import Store
    uid = lambda user: pwd.getpwnam(user).pw_uid
    if role == 'observer':
        if os.geteuid() != 0:
            raise Fault('not_authorized')
        from .observer import Collector
        collect = Collector(uid(current().amp_user))
        server = await serve_unix('/run/discord-amp-observer/observer.sock', uid('discord-amp-broker'), partial(observer_handler, collect))
    elif role == 'broker':
        from .amp import AMP
        from .broker import Broker
        bind_store(Path('/var/lib/discord-amp-broker'))
        journal = Store('/var/lib/discord-amp-broker', 8 * 1024 * 1024)
        broker = Broker(AMP(credential('amp-password')), partial(observer_call, '/run/discord-amp-observer/observer.sock'), journal, partial(enabled, 'broker'))
        await broker.reconcile()
        server = await broker_http(broker, credential('broker-token'), port=current().broker_port)
    else:
        from .controller import Controller
        from .network import wake, query
        bind_store(Path('/var/lib/discord-amp-controller'))
        journal = Store('/var/lib/discord-amp-controller')
        control = Controller(journal, BrokerClient('/run/discord-amp-tunnel/broker.sock', credential('broker-token')), wake, query, partial(enabled, 'controller'))
        await control.recover()
        server = await serve_unix('/run/discord-amp-controller/controller.sock', uid('discord-amp-bot'), partial(controller_handler, control))
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['check', 'doctor', 'render', 'bot', 'controller', 'broker', 'observer', 'review'])
    parser.add_argument('--store', choices=['broker', 'controller'])
    parser.add_argument('--job')
    parser.add_argument('--config', default='/etc/discord-amp/profile.json')
    parser.add_argument('--output')
    args = parser.parse_args()
    if args.role in {'check', 'doctor', 'render'}:
        from .diagnostics import local_command
        return local_command(args, parser)
    if sys.platform != 'linux':
        parser.exit(2, 'Linux service entry points only; portable tests require no credentials.\n')
    try:
        configure(load(Path(args.config), protected=True))
        import pwd
        if args.role == 'review':
            if os.geteuid() != 0 or not args.store or not job_id(args.job):
                raise Fault('invalid_request')
            from .store import Store
            bind_store(Path('/var/lib/discord-amp-' + args.store))
            journal = Store('/var/lib/discord-amp-' + args.store, (8 if args.store == 'broker' else 12) * 1024 * 1024)
            job = journal.get(args.job)
            if not job or job['state'] != 'unknown':
                raise Fault('invalid_request')
            # Explicit local owner acknowledgement only, never a replay.
            journal.update(args.job, 'failed', 'failed', 'reconcile')
            journal.close()
        elif args.role == 'bot':
            if os.geteuid() != pwd.getpwnam('discord-amp-bot').pw_uid:
                raise Fault('not_authorized')
            from .bot import run
            run(credential('discord-token'), '/run/discord-amp-controller/controller.sock', pwd.getpwnam('discord-amp-controller').pw_uid)
        else:
            expected = 0 if args.role == 'observer' else pwd.getpwnam('discord-amp-' + args.role).pw_uid
            if os.geteuid() != expected:
                raise Fault('not_authorized')
            asyncio.run(service(args.role))
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        # Service manager gets a finite failure code, never credentials/traceback.
        print(exc.code if isinstance(exc, (Fault, ConfigError)) else 'service_failed', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
