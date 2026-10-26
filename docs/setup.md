# Manual Linux setup — experimental

This path is documented for review; independent installation has not been run.
Use a separate installation and inspect generated units. Do not point this alpha
at an existing controller's state directory or replace a working deployment.
No setup command should stop a game, suspend a host or enable mutations silently.

Prerequisites: Python 3.12+, systemd with LoadCredential and the confinement
directives used in the templates, OpenSSH, Linux proc/cgroup v2, an existing AMP
installation with the supported local inventory/process layout, persistent game
storage, LAN WOL and an always-on controller on the appropriate network. The
templates use x86-64 AMP by default; other binary/architecture packaging is
unqualified. Containers, non-systemd hosts and arbitrary AMP layouts are not
claimed supported. OS package names vary; use your distribution's normal tools.

## 1. Prepare a separate package and policy

Install into `/opt/discord-amp-controller/.venv` using standard Python tooling;
include the pinned Discord extra on the controller host. Keep code root-owned
and unwritable by service users. No Windows/Codex administration is required.
Create the real profile locally and place identical root-owned 0644 copies at
`/etc/discord-amp/profile.json` under root-owned nonwritable directories.
Validate it with `guildwake check --config PATH` before any service operation.

Create the Discord app and invite only the bot/application command scopes needed
for the fixed channel. Keep privileged intents off and do not grant Administrator.
Configure the role ID; manage its members in Discord. Keep the AMP panel LAN/VPN
only. Create a dedicated AMP account limited to the allowed instance status/start
and inventory reads required by this adapter. Do not give it console, files,
stop, broad administration or unrelated game control. Validate the actual AMP
permission matrix for the installed version before enabling any effect.

## 2. Establish identities and credentials

| Host | Required service identities |
| --- | --- |
| Always-on controller | `discord-amp-bot`, `discord-amp-controller`, `discord-amp-tunnel` |
| AMP host | `discord-amp-broker`, `discord-amp-tunnel`; observer runs root in its confined unit; existing AMP OS user stays separate |

Use locked system accounts with their matching groups. The bot needs supplemental
controller-group access to its Unix socket; the controller must reach the tunnel
socket. The tunnel unit uses the controller group. Observer/broker communicate
through their narrow local socket. Inspect actual mode/UID/group behavior rather
than loosening permissions until it works.

Root-owned 0400 credential source files live under root-only 0700 `credentials`
directories in `/etc/discord-amp-ROLE/`:

- bot: `discord-token`
- controller: `broker-token`
- broker: the matching `broker-token` plus `amp-password`
- controller's tunnel: `tunnel-key`, a separate dedicated forwarding identity

Enter values locally with a secret-safe editor/password manager; do not put them
in command arguments, shell history, JSON profiles or logs. systemd LoadCredential
supplies protected per-service copies. No helper asks for a secret in chat.

## 3. Restrict the SSH forward

Pin the AMP host key after independent verification in the controller's
`/etc/discord-amp-tunnel/known_hosts` using the configured host alias. Never accept
a changed host key automatically. The dedicated public key belongs to the AMP
host's tunnel user only, with `restrict,port-forwarding,permitopen="127.0.0.1:PORT"`
authorized-key restrictions. Keep the private key on the controller only.

Render the candidate SSH Match policy and review it alongside existing settings.
Set a root-managed AuthorizedKeysFile for the tunnel user. Check `sshd -t` and
effective `sshd -T -C ...` policy before any approved reload. MaxSessions 0,
no shell/TTY/agent/X11 forwarding and only the configured loopback broker target
are required. Existing administrator identities must remain unaffected.

## 4. Render and inspect services

`guildwake render --config PATH --output NEW_DIRECTORY` creates five unit files
and one SSH policy example. It does not install them. The controller uses bot,
controller and tunnel units; the AMP host uses broker and observer units.
The ordinary package retains `discord-amp-*` internal user/path names even though
the product is Guildwake. Validate confinement, IP egress, storage readiness,
socket ownership, existing conflicts and `systemd-analyze verify` before an
operator chooses to install/start anything. Keep the profile and credentials
separate from the source tree. No unit is enabled by this renderer.

## 5. Read-only checks before mutations

Start only the separately approved read-only deployment after prerequisite
review. `guildwake doctor --config PATH` reports local metadata with zero network
probes; verify live broker/AMP/Discord status separately. The new controller and
broker mutation gates are absent by default, so wake/start refuse. Both must be
deliberately enabled by the operator only after the chosen qualification. Do not
copy enablement markers from another installation.

No live alpha qualification or independent installation is claimed here. Keep
saves/recovery available, use the intended member role, retain Job IDs/private
results, and stop on an unexpected effect. There is no automated rollback or
package repair. Disable new requests before any separately planned maintenance;
changing a gate does not cancel an already dispatched action.
