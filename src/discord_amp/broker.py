"""Fixed host-side capability boundary; no caller-selected AMP targets/methods."""
import asyncio
import time
from .model import Fault, StartBlocked, START_BLOCK_CODES, STATES, job_id, snowflake


class Broker:
    def __init__(self, backend, observe, store, enabled=lambda: False, monotonic=time.monotonic):
        self.backend, self.observe, self.store, self.enabled = backend, observe, store, enabled
        self.lock = asyncio.Lock()
        self.now = monotonic

    async def status(self):
        result = await self.backend.status()
        if (not isinstance(result, dict) or set(result) != {"controller", "state"}
                or type(result["controller"]) is not bool or result["state"] not in STATES):
            raise Fault("amp_unknown")
        return {"amp_available": True, **result}

    async def reconcile(self):
        # Read once; never reissue a controller/application mutation after restart.
        for job in self.store.active():
            try:
                state = (await self.status())["state"]
                done = state == "ready"
            except Fault:
                done = False
            self.store.update(job["id"], "complete" if done else "unknown", "ready" if done else "unknown", "reconcile")

    async def start(self, identity, user):
        if not job_id(identity) or not snowflake(user):
            raise Fault("invalid_request")
        async with self.lock:
            old = self.store.get(identity)
            if old:
                if old["action"] != "start" or old["user"] != user:
                    raise Fault("invalid_request")
                if old['state'] == 'blocked' and old['stage'] == 'accepted' and old['code'] in START_BLOCK_CODES:
                    raise StartBlocked(identity, user, old['code'])
                return {"id": identity, "code": old["code"]}
            if not self.enabled():
                raise Fault("mutations_disabled")
            if self.store.unresolved():
                raise Fault("review_required")
            last = self.store.latest_mutation()
            if last is not None and self.store.clock() - last < 60:
                raise Fault("cooldown")
            self.store.create(identity, "start", user)
            attempted = False
            try:
                status = await self.status()
                if status["state"] in {"ready", "starting"}:
                    self.store.update(identity, "complete", "already_running")
                    return {"id": identity, "code": "already_running"}
                if status["state"] not in {"stopped", "controller_stopped"}:
                    raise Fault("guard_unknown")
                observed_at = self.now()
                guard = await self.observe()
                if guard.state != "clear" or not guard.covered or guard.selected_active:
                    if guard.state == "busy" and guard.covered and guard.reason == "amp_maintenance":
                        raise Fault("guard_maintenance")
                    raise Fault("guard_busy" if guard.state == "busy" else "guard_unknown")
                if not self.enabled():
                    raise Fault("mutations_disabled")
                # Nothing network-blocking is placed between fresh observation
                # and durable mutation intent. No automatic mutation retries.
                stage = "application" if status["controller"] else "child"
                self.store.update(identity, "attempted", "starting", stage)
                attempted = True
                def permit_send():
                    # Evaluate again inside the AMP adapter immediately before
                    # HTTP dispatch, after fsync/thread/session/lock delays.
                    if not self.enabled():
                        raise Fault("mutations_disabled")
                    if guard.age_ms is None or guard.age_ms / 1000 + self.now() - observed_at > 2:
                        raise Fault("guard_unknown")
                if status["controller"]:
                    await self.backend.start_application(permit_send)
                else:
                    # Existing child StartApplication autostart is preserved.
                    # Poll it; never add an automatic second application start.
                    await self.backend.start_child(permit_send)
                self.store.update(identity, "complete", "starting")
                return {"id": identity, "code": "starting"}
            except BaseException as exc:
                code = exc.code if isinstance(exc, Fault) and exc.code in {"guard_busy", "guard_maintenance", "guard_unknown", "mutations_disabled"} else "unknown"
                state = "unknown" if attempted or code == "unknown" else "blocked"
                # The receipt is emitted only after this exact no-dispatch result
                # is durable. Anything after the attempted marker remains uncertain.
                self.store.update(identity, state, code)
                if not isinstance(exc, (Exception, asyncio.CancelledError)):
                    raise
                if isinstance(exc, asyncio.CancelledError):
                    raise
                if state == 'blocked':
                    raise StartBlocked(identity, user, code) from None
                raise Fault(code) from None
