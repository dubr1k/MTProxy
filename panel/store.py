from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=2$WgRGk2j919KU4cq8Aoq1eQ$Yu6TDt/n0xMCzUMjf0cpxeC/CkNXj2ilMtTlv2L+2wU"
)


class ConflictError(Exception):
    pass


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.passwords = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
        self._dummy_hash = DUMMY_PASSWORD_HASH
        self._init()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _init(self):
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS admins (
              id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),
              active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
              csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              last_seen_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
              scope TEXT NOT NULL, happened_at INTEGER NOT NULL,
              reservation_id TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS login_attempts_scope_time ON login_attempts(scope,happened_at);
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY, happened_at INTEGER NOT NULL, actor_id INTEGER,
              actor_username TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
              detail_json TEXT NOT NULL DEFAULT '{}', ip TEXT NOT NULL
            );
            """)
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(login_attempts)")
            }
            if "reservation_id" not in columns:
                db.execute(
                    "ALTER TABLE login_attempts "
                    "ADD COLUMN reservation_id TEXT NOT NULL DEFAULT ''"
                )

    def create_admin(self, username: str, password: str, role: str):
        if role not in {"owner", "admin", "viewer"} or len(password) < 12:
            raise ValueError("invalid administrator")
        with self.connect() as db:
            cur = db.execute("INSERT INTO admins(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                             (username, self.passwords.hash(password), role, int(time.time())))
            return cur.lastrowid

    def verify_admin(self, username: str, password: str):
        with self.connect() as db:
            row = db.execute("SELECT * FROM admins WHERE username=? COLLATE NOCASE AND active=1", (username,)).fetchone()
            if not row:
                try:
                    self.passwords.verify(self._dummy_hash, password)
                except VerifyMismatchError:
                    pass
                return None
            try:
                self.passwords.verify(row["password_hash"], password)
            except VerifyMismatchError:
                return None
            if self.passwords.check_needs_rehash(row["password_hash"]):
                db.execute("UPDATE admins SET password_hash=? WHERE id=?", (self.passwords.hash(password), row["id"]))
            return dict(row)

    def create_session(self, admin_id: int, ttl: int):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)", (
                self._hash(token), admin_id, self._hash(csrf), now, now + ttl, now))
        return token, csrf

    def session(self, token: str | None):
        if not token:
            return None
        now = int(time.time())
        with self.connect() as db:
            row = db.execute("""SELECT s.*,a.username,a.role,a.active FROM sessions s
                JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.active=1""",
                (self._hash(token), now)).fetchone()
            if row:
                db.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (now, row["token_hash"]))
            return dict(row) if row else None

    def csrf_valid(self, session: dict, supplied: str | None, cookie: str | None):
        return bool(supplied and cookie and secrets.compare_digest(supplied, cookie)
                    and secrets.compare_digest(self._hash(supplied), session["csrf_hash"]))

    def delete_session(self, token: str | None):
        if token:
            with self.connect() as db:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (self._hash(token),))

    def reserve_login_attempt(
        self,
        scopes: list[str],
        attempts: int,
        window: int,
    ) -> str | None:
        """Atomically reserve capacity before expensive password verification."""
        if not scopes or attempts < 1 or window < 1:
            raise ValueError("invalid login limiter configuration")
        now = int(time.time())
        reservation_id = secrets.token_urlsafe(18)
        cutoff = now - window
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM login_attempts WHERE happened_at<?", (cutoff,))
            limited = any(
                db.execute(
                    "SELECT count(*) FROM login_attempts WHERE scope=?",
                    (scope,),
                ).fetchone()[0]
                >= attempts
                for scope in scopes
            )
            if limited:
                return None
            db.executemany(
                "INSERT INTO login_attempts(scope,happened_at,reservation_id) "
                "VALUES(?,?,?)",
                [(scope, now, reservation_id) for scope in scopes],
            )
            return reservation_id

    def release_login_attempt(self, reservation_id: str) -> None:
        with self._lock, self.connect() as db:
            db.execute(
                "DELETE FROM login_attempts WHERE reservation_id=?",
                (reservation_id,),
            )

    def admins(self):
        with self.connect() as db:
            return [dict(x) for x in db.execute("SELECT id,username,role,active,created_at FROM admins ORDER BY username")]

    def update_admin(self, admin_id: int, role: str | None = None, password: str | None = None, active: bool | None = None):
        with self._lock, self.connect() as db:
            row = db.execute("SELECT * FROM admins WHERE id=?", (admin_id,)).fetchone()
            if not row:
                return False
            if row["role"] == "owner" and role and role != "owner" and self._owner_count(db) <= 1:
                raise ConflictError("last owner")
            if row["role"] == "owner" and active is False and self._owner_count(db) <= 1:
                raise ConflictError("last owner")
            if role:
                db.execute("UPDATE admins SET role=? WHERE id=?", (role, admin_id))
            if password:
                db.execute("UPDATE admins SET password_hash=? WHERE id=?", (self.passwords.hash(password), admin_id))
                db.execute("DELETE FROM sessions WHERE admin_id=?", (admin_id,))
            if active is not None:
                db.execute("UPDATE admins SET active=? WHERE id=?", (int(active), admin_id))
                if not active:
                    db.execute("DELETE FROM sessions WHERE admin_id=?", (admin_id,))
            return True

    def delete_admin(self, admin_id: int):
        with self._lock, self.connect() as db:
            row = db.execute("SELECT role FROM admins WHERE id=?", (admin_id,)).fetchone()
            if not row:
                return False
            if row["role"] == "owner" and self._owner_count(db) <= 1:
                raise ConflictError("last owner")
            db.execute("DELETE FROM admins WHERE id=?", (admin_id,))
            return True

    @staticmethod
    def _owner_count(db):
        return db.execute("SELECT count(*) FROM admins WHERE role='owner' AND active=1").fetchone()[0]

    def audit(self, actor: dict, action: str, target: str, ip: str, detail: dict | None = None):
        safe = {k: v for k, v in (detail or {}).items() if k not in {"secret", "password", "token", "link"}}
        with self.connect() as db:
            db.execute("INSERT INTO audit_log(happened_at,actor_id,actor_username,action,target,detail_json,ip) VALUES(?,?,?,?,?,?,?)",
                       (int(time.time()), actor.get("admin_id") or actor.get("id"), actor["username"], action, target, json.dumps(safe), ip))

    def audits(
        self,
        limit: int = 200,
        *,
        before_id: int | None = None,
        actor: str | None = None,
        action: str | None = None,
        target: str | None = None,
    ):
        clauses = []
        values = []
        if before_id is not None:
            clauses.append("id < ?")
            values.append(before_id)
        if actor is not None:
            clauses.append("actor_username = ? COLLATE NOCASE")
            values.append(actor)
        if action is not None:
            clauses.append("action = ?")
            values.append(action)
        if target is not None:
            clauses.append("target = ?")
            values.append(target)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self.connect() as db:
            rows = db.execute(
                f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ?",
                values,
            )
            return [
                {**dict(row), "detail": json.loads(row["detail_json"])}
                for row in rows
            ]

    def dump_schema(self):
        with self.connect() as db:
            return [x[0] for x in db.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")]

    @staticmethod
    def _hash(value: str):
        return hashlib.sha256(value.encode()).hexdigest()
