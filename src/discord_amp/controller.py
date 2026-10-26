"""Rasp job orchestration: only explicit jobs wake; no action replay on recovery."""
import asyncio
import time
from .model import Fault, StartBlocked

STATUS_TIMEOUT = 6  # Whole status request, including lock wait; RPC budget is 10s.


class Controller:
    def __init__(self, store, broker, wake, query, enabled=lambda: False,
                 monotonic=time.monotonic, sleep=asyncio.sleep):
        self.store, self.broker, self.wake, self.query = store, broker, wake, query
        self.enabled, self.now, self.sleep = enabled, monotonic, sleep
        self.lock = asyncio.Lock()
        self.running = None
        self.status_times = {}
        self.tasks = set()
        self.failure = None

    async def recover(self):
        # Reads have no uncertain game effect. Clear interrupted/legacy unknown
        # status records without contacting the host or touching mutation holds.
        for job in self.store.interrupted_statuses():
            self._finish_status(job, "failed", "broker_unavailable", "reconcile")
        for job in self.store.active():
            try:
                async with asyncio.timeout(STATUS_TIMEOUT):
                    state = (await self.broker.status())["state"]
                    ready = state == "ready" and job["action"] == "start" and await self.query()
                    available = job["action"] == "wake"
            except (Fault, OSError, TimeoutError):
                ready = available = False
            self.store.update(job["id"], "complete" if ready or available else "unknown",
                              "ready" if ready else "amp_available" if available else "unknown", "reconcile")

    async def submit(self, request):
        try:
            request.authorize()
        except Fault as exc:
            self.store.deny(request.user, exc.code)
            raise
        if request.action == "status":
            return await self._status(request)
        async with self.lock:
            if self.failure:
                raise Fault(self.failure)
            old = self.store.get(request.id)
            if old:
                if (old["user"], old["action"]) != (request.user, request.action):
                    raise Fault("invalid_request")
                return {"job": old["id"], "code": old["code"]}
            if not self.enabled():
                raise Fault("mutations_disabled")
            if self.running:
                # A wake requester may follow a start job. A start must not be
                # silently coalesced into a wake-only job (which cannot start).
                if self.running["action"] == "wake" and request.action == "start":
                    raise Fault("host_busy")
                return {"job": self.running["id"], "code": "working"}
            if self.store.unresolved():
                raise Fault("review_required")
            before = self.store.latest_mutation()
            if before is not None and self.store.clock() - before < 60:
                self.store.deny(request.user, "cooldown")
                raise Fault("cooldown")
            job = self.store.create(request.id, request.action, request.user)
            self.running = job
            task = asyncio.create_task(self._run(job))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return {"job": job["id"], "code": "accepted"}

    def _finish_status(self, job, state, code, stage=None):
        try:
            self.store.update(job["id"], state, code, stage)
        except Fault:
            self.failure = "audit_unavailable"
            self.enabled = lambda: False
            raise Fault("audit_unavailable") from None
        return {"job": job["id"], "code": code}

    async def _status(self, request):
        job = None
        try:
            async with asyncio.timeout(STATUS_TIMEOUT):
                async with self.lock:
                    if self.failure:
                        raise Fault(self.failure)
                    old = self.store.get(request.id)
                    if old:
                        if (old["user"], old["action"]) != (request.user, "status"):
                            raise Fault("invalid_request")
                        return {"job": old["id"], "code": old["code"]}
                    before = self.status_times.get(request.user)
                    if before is not None and self.now() - before < 10:
                        self.store.deny(request.user, "cooldown")
                        raise Fault("cooldown")
                    if len(self.status_times) >= 512:
                        self.status_times = {u: t for u, t in self.status_times.items() if self.now() - t < 10}
                        if len(self.status_times) >= 512:
                            raise Fault("cooldown")
                    self.status_times[request.user] = self.now()
                    job = self.store.create(request.id, "status", request.user)
                    try:
                        result = await self.broker.status()
                        code = result["state"]
                    except asyncio.CancelledError:
                        # Outer RPC/client shutdown cancellation is not an
                        # uncertain mutation. Persist before propagating it.
                        self._finish_status(job, "failed", "broker_unavailable")
                        raise
                    except (Fault, OSError, TimeoutError) as exc:
                        code = "broker_unavailable" if not isinstance(exc, Fault) or exc.code == "broker_unavailable" else "unknown"
                        return self._finish_status(job, "failed", code)
                    except Exception:
                        return self._finish_status(job, "failed", "unknown")
                    response = self._finish_status(job, "complete", code)
                    return {**response, "status": result}
        except TimeoutError:
            if job is not None:
                return {"job": job["id"], "code": "broker_unavailable"}
            # Deadline while queued: no job was created, no host was contacted.
            raise Fault("broker_unavailable") from None

    async def progress(self, request, identity):
        request.authorize()
        if self.failure:
            raise Fault(self.failure)
        job = self.store.get(identity)
        if not job:
            raise Fault("invalid_request")
        # Authorized members may attach to the single shared host job.
        return {"job": job["id"], "code": job["code"], "terminal": job["state"] in {"complete", "blocked", "failed", "unknown"}}

    async def _run(self, job):
        attempted = False
        try:
            self.store.update(job["id"], "working", "working")
            try:
                status = await self.broker.status()
            except Fault as exc:
                if exc.code != "broker_unavailable":
                    raise
                if not self.enabled():
                    raise Fault("mutations_disabled")
                self.store.update(job["id"], "attempted", "wake_requested", "wake")
                attempted = True
                await self.wake()
                deadline = self.now() + 120
                while True:
                    if self.now() >= deadline:
                        raise Fault("deadline")
                    try:
                        async with asyncio.timeout(max(.001, deadline - self.now())):
                            status = await self.broker.status()
                        if self.now() > deadline:
                            raise Fault("deadline")
                        break
                    except Fault as failure:
                        if failure.code != "broker_unavailable":
                            raise
                    if self.now() >= deadline:
                        raise Fault("deadline")
                    await self.sleep(min(5, deadline - self.now()))
            if job["action"] == "wake":
                self.store.update(job["id"], "complete", "amp_available")
                return
            deadline = self.now() + 600
            if status["state"] not in {"ready", "starting"}:
                if not self.enabled():
                    raise Fault("mutations_disabled")
                self.store.update(job["id"], "attempted", "starting", "application")
                attempted = True
                async with asyncio.timeout(max(.001, deadline - self.now())):
                    await self.broker.start(job["id"], job["user"])
            self.store.update(job["id"], "working", "starting", "poll")
            while True:
                if self.now() >= deadline:
                    raise Fault("deadline")
                async with asyncio.timeout(max(.001, deadline - self.now())):
                    status = await self.broker.status()
                    ready = status["state"] == "ready" and await self.query()
                if self.now() > deadline:
                    raise Fault("deadline")
                if ready:
                    self.store.update(job["id"], "complete", "ready")
                    return
                if self.now() >= deadline:
                    raise Fault("deadline")
                await self.sleep(min(5, deadline - self.now()))
        except BaseException as exc:
            code = "deadline" if isinstance(exc, TimeoutError) else exc.code if isinstance(exc, Fault) and exc.code in {"guard_busy", "guard_maintenance", "guard_unknown", "mutations_disabled", "deadline"} else "unknown"
            try:
                verified_block = (isinstance(exc, StartBlocked)
                                  and (exc.identity, exc.user) == (job['id'], job['user']))
                self.store.update(job["id"], "blocked" if verified_block else "unknown" if attempted or code == "unknown" else "blocked", code)
            except Fault:
                # Refuse all further work in this process after durable failure.
                self.enabled = lambda: False
                self.failure = "audit_unavailable"
            if isinstance(exc, asyncio.CancelledError):
                raise
        finally:
            async with self.lock:
                self.running = None
