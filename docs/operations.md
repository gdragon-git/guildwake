# Operation and recovery limits

Status does not wake. Wake does not start a game. Start wakes if needed and
checks AMP plus the bounded Enshrouded LAN query. Already-running start is a no-op.
Replies are private; report failures with the Job ID instead of repeatedly
submitting requests. Do not clear an unknown hold merely because a later status
looks ready. An exception or a lost response is not proof no effect was sent.

The bot exposes no Stop, Restart or Sleep. For manual sleep, finish players,
check all running games, tasks, schedules and bot jobs, gracefully stop the games,
confirm their processes exited, preserve stable saves and verify a stopped-game
backup. Confirm WOL and a recovery path, then choose suspend explicitly. There
is no automatic idle-sleep controller. Packet transmission is not successful wake.

Run only one active controller for this profile. SQLite and the per-host lock
coordinate this installation, not arbitrary outside administrators. Keep AMP
tasks and incomplete/unknown process coverage blocking game start. Unmanaged
games, root compromise or external administrators can bypass this cooperative
model. Query readiness is not player join or cold-boot proof.

Do not automatically retry uncertain effects after restart. Local owner review
is an explicit acknowledgement after investigation, not an effect replay.
Profiles/journals bind an installation; no migration of old state is automatic.
Preserve backups, credential boundaries and old code/data before separately
approved upgrades. Code rollback never grants permission to erase a journal,
clear a hold or repeat a start.
