"""Small bounded SQLite journal: durable intent before any side effect."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import threading
import time
from .model import Fault, job_id, snowflake

TERMINAL = {"complete", "failed", "unknown", "blocked"}
ACTIVE = {"accepted", "working", "attempted"}
RESULTS = {"accepted", "working", "ready", "starting", "stopped", "controller_stopped",
           "complete", "failed", "unknown", "blocked", "guard_busy", "guard_maintenance", "guard_unknown",
           "wake_requested", "amp_available", "deadline", "mutations_disabled",
           "already_running", "not_authorized", "unsupported_command", "cooldown",
           "request_expired", "broker_unavailable", "audit_unavailable"}


class Store:
    def __init__(self, directory, db_limit=12 * 1024 * 1024, clock=time.time):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.limit = db_limit
        self.clock = clock
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.directory / "jobs.sqlite", check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA temp_store=MEMORY")
        self.db.execute("PRAGMA cache_size=-2048")
        self.db.execute("PRAGMA busy_timeout=2000")
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        if self.db.execute(f"PRAGMA max_page_count={db_limit // page_size}").fetchone()[0] > db_limit // page_size:
            self.db.close()
            raise Fault("audit_unavailable")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, action TEXT NOT NULL, user TEXT NOT NULL,
                state TEXT NOT NULL, code TEXT NOT NULL, created REAL NOT NULL,
                updated REAL NOT NULL, stage TEXT NOT NULL DEFAULT 'accepted');
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY, job TEXT NOT NULL, code TEXT NOT NULL, at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS event_time ON events(at);
        """)

    def close(self):
        self.db.close()

    def _space(self):
        # Database plus rollback journal <= twice the page cap; unexpected files
        # also count. No unbounded WAL or application file logs.
        total = sum(p.stat().st_size for p in self.directory.iterdir() if p.is_file())
        db_size = (self.directory / "jobs.sqlite").stat().st_size
        if total + max(self.limit - db_size, self.limit) > 2 * self.limit + 65536:
            raise Fault("audit_unavailable")

    @contextmanager
    def transaction(self):
        with self.lock:
            try:
                self._space()
                self.db.execute("BEGIN IMMEDIATE")
                cutoff = self.clock() - 30 * 86400
                self.db.execute("DELETE FROM events WHERE at < ? AND job NOT IN (SELECT id FROM jobs WHERE state IN ('accepted','working','attempted'))", (cutoff,))
                self.db.execute("DELETE FROM jobs WHERE updated < ? AND state IN ('complete','failed','blocked')", (cutoff,))
                pages = self.db.execute("PRAGMA page_count").fetchone()[0]
                free = self.db.execute("PRAGMA freelist_count").fetchone()[0]
                size = self.db.execute("PRAGMA page_size").fetchone()[0]
                if pages * size > self.limit * .8 and free < 32:
                    # Reuse pages rather than growing a WAL or vacuuming at the
                    # boundary. Preserve uncertain/active jobs for review.
                    self.db.execute("DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE job NOT IN (SELECT id FROM jobs WHERE state IN ('accepted','working','attempted','unknown')) ORDER BY at LIMIT 256)")
                    self.db.execute("DELETE FROM jobs WHERE id IN (SELECT id FROM jobs WHERE state IN ('complete','failed','blocked') AND updated < ? ORDER BY updated LIMIT 64)", (self.clock() - 900,))
                yield
                self.db.execute("COMMIT")
            except (sqlite3.Error, OSError):
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise Fault("audit_unavailable") from None
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise

    def get(self, identity):
        with self.lock:
            row = self.db.execute("SELECT id,action,user,state,code,created,updated,stage FROM jobs WHERE id=?", (identity,)).fetchone()
            return dict(zip(("id", "action", "user", "state", "code", "created", "updated", "stage"), row)) if row else None

    def active(self):
        with self.lock:
            rows = self.db.execute("SELECT id FROM jobs WHERE state IN ('accepted','working','attempted') ORDER BY created").fetchall()
            return [self.get(row[0]) for row in rows]

    def interrupted_statuses(self):
        with self.lock:
            rows = self.db.execute("SELECT id FROM jobs WHERE action='status' AND state IN ('accepted','working','attempted','unknown') ORDER BY created").fetchall()
            return [self.get(row[0]) for row in rows]

    def latest_mutation(self):
        with self.lock:
            return self.db.execute("SELECT MAX(created) FROM jobs WHERE action IN ('wake','start')").fetchone()[0]

    def unresolved(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM jobs WHERE state IN ('unknown','accepted','working','attempted')").fetchone()[0] > 0

    def create(self, identity, action, user):
        if not job_id(identity) or action not in {"status", "wake", "start"} or not snowflake(user):
            raise Fault("invalid_request")
        with self.transaction():
            old = self.get(identity)
            if old:
                if (old["action"], old["user"]) != (action, user):
                    raise Fault("invalid_request")
                return old
            now = self.clock()
            self.db.execute("INSERT INTO jobs(id,action,user,state,code,created,updated) VALUES(?,?,?,'accepted','accepted',?,?)", (identity, action, user, now, now))
            self.db.execute("INSERT INTO events(job,code,at) VALUES(?, 'accepted', ?)", (identity, now))
        return self.get(identity)

    def update(self, identity, state, code, stage=None):
        if state not in ACTIVE | TERMINAL or code not in RESULTS or stage not in {None, "accepted", "wake", "child", "application", "poll", "reconcile"}:
            raise Fault("invalid_request")
        with self.transaction():
            old = self.get(identity)
            if not old:
                raise Fault("invalid_request")
            now = self.clock()
            self.db.execute("UPDATE jobs SET state=?,code=?,updated=?,stage=? WHERE id=?", (state, code, now, stage or old["stage"], identity))
            self.db.execute("INSERT INTO events(job,code,at) VALUES(?,?,?)", (identity, code, now))
        return self.get(identity)

    def deny(self, user, code):
        # Authorization failures contain only a validated ID and fixed code.
        if code not in {"not_authorized", "unsupported_command", "cooldown"}:
            raise Fault("invalid_request")
        with self.transaction():
            self.db.execute("INSERT INTO events(job,code,at) VALUES(?,?,?)", (user if snowflake(user) else "redacted", code, self.clock()))
