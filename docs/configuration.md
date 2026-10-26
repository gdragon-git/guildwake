# Configuration

Start from `examples/profile.example.json`. It is synthetic and not usable for
your real Discord/AMP installation. Set actual policy locally; never commit it.
Use one identical protected profile on both hosts. Service IPC and broker HTTP
reject a mismatched profile fingerprint before handler/backend dispatch.

The parser accepts only the documented exact keys. It rejects duplicate/unknown
keys, secret fields, malformed IDs/addresses/ports, path traversal, nested instance
roots, duplicate names/UUIDs/paths, an absent selected or management instance and
unsupported AMP binary identities. The profile is immutable after configuration;
there is no private deployment fallback or import-time file/environment discovery.

- `discord`: application/guild/channel/owner/member-role IDs as decimal strings.
- `host`: command alias, literal game-host IPv4, unicast NIC MAC, LAN broadcast.
- `amp`: fixed literal origin, limited account name, selected and management
  instance names, inventory path and **every** AMP instance name/UUID/path.
- `observer`: verified storage mount/UUID, AMP OS user and protected maintenance/
  systemd executable/unit paths. The provider is Linux proc/cgroup v2. Only layouts
  covered by the conservative observer are usable; unknown layouts refuse.
- `query.port` and `broker.port`: bounded integer ports. Broker listening stays
  loopback-only. The allowed game/protocol is Enshrouded, not arbitrary methods.

AMP origin is restricted to loopback or the configured host IP with an explicit
HTTP(S) port and no URL userinfo/path/query/fragment. Child routing is derived
from the selected instance UUID and stays under the fixed ADS API prefix. AMP
routes/methods remain allowlisted. Read sessions can refresh once; start is never
automatically retried.

Services load `/etc/discord-amp/profile.json` explicitly, requiring root ownership,
a nonwritable directory chain and a regular nonsymlink bounded file. Local
`check`/`doctor` can validate an ordinary example; that does not make it a trusted
service policy. Secrets belong in separate systemd credentials. Preserve AMP
passwords exactly; tokens must fit a single authorization header.

Controller/broker state is bound to `profile.sha256`. A different policy or an
old nonempty journal without a binding refuses. There is no automatic adoption,
journal rewrite, hold clearing or migration of an existing private installation.
Plan a deliberate data-preserving migration before changing installation policy.
