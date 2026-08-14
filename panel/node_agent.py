"""Durable replay-safe node executor for an explicitly local Telemt API.

Network enrollment/polling is deliberately not implemented. Commands must arrive through
an authenticated transport supplied by a future release (mTLS); this module only validates
and executes already-authenticated typed envelopes.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

from .fleet import ProtocolError, TypedCommand, validate_result


class ExecutionIndeterminate(RuntimeError):
    """The request may have committed but no authoritative response was received."""


class AgentJournal:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS agent_state (
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), node_id TEXT, last_sequence INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO agent_state(singleton,last_sequence) VALUES(1,0);
            CREATE TABLE IF NOT EXISTS agent_commands (
              sequence INTEGER PRIMARY KEY, command_id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('executing','succeeded','failed','indeterminate')),
              result_json TEXT, started_at INTEGER NOT NULL, completed_at INTEGER
            );
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        return db

    def begin(self, item: TypedCommand):
        """Persist intent before side effects; never retry an uncertain executing record."""
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            state = db.execute("SELECT node_id,last_sequence FROM agent_state WHERE singleton=1").fetchone()
            if state["node_id"] is not None and state["node_id"] != item.node_id:
                raise ProtocolError("journal belongs to another node")
            existing = db.execute("SELECT * FROM agent_commands WHERE sequence=?", (item.sequence,)).fetchone()
            if existing:
                if existing["command_id"] != item.command_id or existing["digest"] != item.digest:
                    raise ProtocolError("sequence replay does not match journal")
                if existing["status"] == "executing":
                    raise ProtocolError("command is already executing")
                return existing["status"], json.loads(existing["result_json"] or "{}")
            expected = state["last_sequence"] + 1
            if item.sequence != expected:
                raise ProtocolError(f"sequence gap: expected {expected}")
            db.execute("UPDATE agent_state SET node_id=?,last_sequence=? WHERE singleton=1", (item.node_id, item.sequence))
            db.execute("INSERT INTO agent_commands(sequence,command_id,digest,status,started_at) VALUES(?,?,?,'executing',?)",
                       (item.sequence, item.command_id, item.digest, int(time.time())))
            return None

    def recover_interrupted(self) -> int:
        """Call once during exclusive process startup, before accepting commands."""
        result = {"message": "outcome requires Telemt reconciliation"}
        with self._lock, self.connect() as db:
            rows = db.execute("SELECT sequence FROM agent_commands WHERE status='executing'").fetchall()
            db.execute("""UPDATE agent_commands SET status='indeterminate',result_json=?,completed_at=?
                WHERE status='executing'""", (json.dumps(result, sort_keys=True, separators=(",", ":")), int(time.time())))
            return len(rows)

    def finish(self, item: TypedCommand, status: str, result: dict) -> dict:
        if status not in {"succeeded", "failed", "indeterminate"}:
            raise ProtocolError("journal status is invalid")
        result = validate_result(result, item.operation, status)
        with self._lock, self.connect() as db:
            changed = db.execute("""UPDATE agent_commands SET status=?,result_json=?,completed_at=?
                WHERE sequence=? AND command_id=? AND digest=? AND status='executing'""",
                (status, json.dumps(result, sort_keys=True, separators=(",", ":")), int(time.time()),
                 item.sequence, item.command_id, item.digest)).rowcount
            if changed != 1:
                raise ProtocolError("journal command is not executing")
        return {"status": status, "sequence": item.sequence, "command_id": item.command_id, "result": result}


class LocalTelemtExecutor:
    """Allowlisted adapter with no generic URL, method, path, or body forwarding."""
    def __init__(self, base_url: str, auth_header: str, *, timeout: float = 5.0, transport=None):
        parts = urlsplit(base_url)
        safe = (
            parts.scheme == "http" and parts.hostname in {"127.0.0.1", "::1"}
            and parts.port is not None and parts.path in {"", "/"}
            and not parts.username and not parts.password and not parts.query and not parts.fragment
        )
        if not safe:
            raise ProtocolError("Telemt endpoint must be an explicit loopback HTTP URL")
        if not isinstance(auth_header, str) or not auth_header.startswith("Bearer ") or len(auth_header) < 10:
            raise ProtocolError("local Telemt authorization is required")
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.timeout = timeout
        self.transport = transport

    async def execute(self, item: TypedCommand) -> dict:
        username = item.payload.get("username")
        if item.operation == "telemt.inventory.refresh":
            method, path, body = "GET", "/v1/system/info", None
        elif item.operation in {"telemt.user.enable", "telemt.user.disable"}:
            action = item.operation.rsplit(".", 1)[1]
            method, path = "POST", f"/v1/users/{quote(username, safe='')}/{action}"
            body = None
        elif item.operation == "telemt.user.reset_quota":
            method, path = "POST", f"/v1/users/{quote(username, safe='')}/reset-quota"
            body = None
        elif item.operation == "telemt.user.update_limits":
            method, path = "PATCH", f"/v1/users/{quote(username, safe='')}"
            body = {key: value for key, value in item.payload.items() if key != "username"}
        else:  # unreachable after TypedCommand validation; defensive fail closed
            raise ProtocolError("operation is not executable")
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url, timeout=self.timeout, transport=self.transport,
                headers={"Authorization": self.auth_header}, trust_env=False,
            ) as client:
                headers = {} if method == "GET" else {"If-Match": item.expected_telemt_revision}
                response = await client.request(method, path, json=body, headers=headers)
        except httpx.RequestError as exc:
            raise ExecutionIndeterminate("local Telemt request outcome is unknown") from exc
        if response.status_code >= 400:
            raise ProtocolError(f"local Telemt rejected command ({response.status_code})")
        try:
            envelope = response.json()
        except ValueError as exc:
            raise ProtocolError("local Telemt returned invalid JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("ok") is not True:
            raise ProtocolError("local Telemt rejected command")
        revision = envelope.get("revision")
        if not isinstance(revision, str) or not revision:
            raise ProtocolError("local Telemt omitted revision")
        data = envelope.get("data")
        if item.operation == "telemt.inventory.refresh":
            result = {"inventory": {"telemt_version": str((data or {}).get("version", "unknown"))}, "telemt_revision": revision}
        else:
            source = data if isinstance(data, dict) else {}
            result = {key: source[key] for key in ("username", "enabled", "used_bytes") if key in source}
            result["telemt_revision"] = revision
        return validate_result(result)


class NodeAgent:
    def __init__(self, node_id: str, journal: AgentJournal, executor):
        self.node_id = node_id
        self.journal = journal
        self.executor = executor

    async def apply(self, command) -> dict:
        item = command if isinstance(command, TypedCommand) else TypedCommand.parse(command)
        if item.node_id != self.node_id:
            raise ProtocolError("command targets another node")
        previous = self.journal.begin(item)
        if previous is not None:
            status, result = previous
            return {"status": status, "sequence": item.sequence, "command_id": item.command_id, "result": result}
        try:
            result = await self.executor.execute(item)
        except ExecutionIndeterminate:
            return self.journal.finish(item, "indeterminate", {"message": "outcome requires Telemt reconciliation"})
        except Exception as exc:
            # Never persist exception text: third-party errors can contain headers/bodies.
            code = type(exc).__name__ if isinstance(exc, (ProtocolError, ValueError)) else "ExecutorError"
            return self.journal.finish(item, "failed", {"message": f"command rejected ({code})"})
        return self.journal.finish(item, "succeeded", result)
