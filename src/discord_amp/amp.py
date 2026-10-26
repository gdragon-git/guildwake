"""Installed AMP 2.8.0.8 adapter; fixed routes, bearer auth, no raw objects out."""
from .config import current
import asyncio
import json
import threading
import urllib.error
import urllib.request
from .model import Fault

READ = {("ADSModule", "GetInstanceStatuses"), ("Core", "GetStatus")}
ALLOWED = READ | {("Core", "Login"), ("Core", "Logout"), ("Core", "Start"), ("ADSModule", "StartInstance")}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Session:
    def __init__(self, suffix, password):
        if suffix not in {"", current().child_route}:
            raise Fault("invalid_request")
        self.base, self.password, self.token = current().amp_origin + suffix, password, ""
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, module, method, body, authorize=None):
        if (module, method) not in ALLOWED:
            raise Fault("unsupported_command")
        if method == "StartInstance" and (self.base != current().amp_origin or body != {"InstanceName": (current().selected)}):
            raise Fault("unsupported_command")
        if method == "Start" and (self.base != current().amp_origin + current().child_route or body != {}):
            raise Fault("unsupported_command")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.base + "/API/" + module + "/" + method,
                                         json.dumps(body).encode(), headers, method="POST")
        try:
            if method in {"StartInstance", "Start"}:
                if authorize is None:
                    raise Fault("guard_unknown")
                authorize()
            with self.opener.open(request, timeout=8) as reply:
                raw = reply.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise Fault("amp_unknown")
                value = json.loads(raw)
                auth = reply.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    self.token = auth[7:]
                if isinstance(value, dict):
                    # AMP also reports an invalid session in an HTTP-200 body.
                    # Let read() refresh once; mutation callers never retry.
                    if value.get("Title") == "Unauthorized Access":
                        self.token = ""
                        raise Fault("amp_authentication_failed")
                    if "Error" in value:
                        raise Fault("amp_unknown")
                return value
        except urllib.error.HTTPError:
            self.token = ""
            raise Fault("amp_authentication_failed") from None
        except (OSError, urllib.error.URLError):
            raise Fault("amp_unavailable") from None
        except (ValueError, UnicodeError):
            raise Fault("amp_unknown") from None

    def login(self):
        if self.token:
            return
        value = self.call("Core", "Login", {"username": current().amp_username, "password": self.password, "token": "", "rememberMe": False})
        if not isinstance(value, dict) or value.get("success") is not True:
            raise Fault("amp_authentication_failed")
        self.token = self.token or value.get("sessionID", "")
        if not isinstance(self.token, str) or not self.token or any(c in self.token for c in "\r\n"):
            self.token = ""
            raise Fault("amp_authentication_failed")

    def read(self, module, method):
        if (module, method) not in READ:
            raise Fault("unsupported_command")
        self.login()
        try:
            return self.call(module, method, {})
        except Fault as exc:
            if exc.code != "amp_authentication_failed":
                raise
            # A single session refresh for a read is safe. Start calls are never
            # retried, including after an authentication/transport error.
            self.token = ""
            self.login()
            return self.call(module, method, {})


class AMP:
    def __init__(self, password):
        self.ads = Session("", password)
        self.child = Session(current().child_route, password)
        self.lock = threading.Lock()

    def _status(self):
        with self.lock:
            rows = self.ads.read("ADSModule", "GetInstanceStatuses")
            expected = {data[0] for data in (current().instances).values()}
            if not isinstance(rows, list) or len(rows) != len(expected):
                raise Fault("amp_unknown")
            states = {}
            for row in rows:
                if (not isinstance(row, dict) or set(row) != {"InstanceID", "Running"}
                        or row["InstanceID"] not in expected or row["InstanceID"] in states
                        or type(row["Running"]) is not bool):
                    raise Fault("amp_unknown")
                states[row["InstanceID"]] = row["Running"]
            if not states[(current().selected_id)]:
                self.child.token = ""
                return {"controller": False, "state": "controller_stopped"}
            status = self.child.read("Core", "GetStatus")
            state = status.get("State") if isinstance(status, dict) else None
            if type(state) is not int:
                raise Fault("amp_unknown")
            return {"controller": True, "state": {0: "stopped", 5: "starting", 7: "starting", 10: "starting", 20: "ready", 30: "starting"}.get(state, "unknown")}

    async def status(self):
        return await asyncio.to_thread(self._status)

    def _start(self, child, permit_send):
        with self.lock:
            session = self.ads if child else self.child
            session.login()
            value = session.call("ADSModule" if child else "Core", "StartInstance" if child else "Start", {"InstanceName": (current().selected)} if child else {}, authorize=permit_send)
            if not isinstance(value, dict) or value.get("Status") is not True:
                raise Fault("amp_unknown")

    async def start_child(self, permit_send):
        await asyncio.to_thread(self._start, True, permit_send)

    async def start_application(self, permit_send):
        await asyncio.to_thread(self._start, False, permit_send)
