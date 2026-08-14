"""Durable replay-safe node executor and outbound mTLS polling client."""
from __future__ import annotations

import asyncio
import json
import sqlite3
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

from .mieru import MieruError
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
              result_json TEXT, started_at INTEGER NOT NULL, completed_at INTEGER, uploaded_at INTEGER
            );
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(agent_commands)")}
            if "uploaded_at" not in columns:
                db.execute("ALTER TABLE agent_commands ADD COLUMN uploaded_at INTEGER")
            if "operation" not in columns:
                db.execute(
                    "ALTER TABLE agent_commands ADD COLUMN operation TEXT NOT NULL "
                    "DEFAULT 'telemt.inventory.refresh'"
                )

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
            db.execute(
                "INSERT INTO agent_commands(sequence,command_id,digest,status,started_at,operation) "
                "VALUES(?,?,?,'executing',?,?)",
                (
                    item.sequence,
                    item.command_id,
                    item.digest,
                    int(time.time()),
                    item.operation,
                ),
            )
            return None

    def recover_interrupted(self) -> int:
        """Call once during exclusive process startup, before accepting commands."""
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT sequence,operation FROM agent_commands WHERE status='executing'"
            ).fetchall()
            for row in rows:
                protocol = "Mieru" if row["operation"].startswith("mieru.") else "Telemt"
                result = {"message": f"outcome requires {protocol} reconciliation"}
                db.execute(
                    """UPDATE agent_commands SET status='indeterminate',result_json=?,completed_at=?
                    WHERE sequence=? AND status='executing'""",
                    (
                        json.dumps(result, sort_keys=True, separators=(",", ":")),
                        int(time.time()),
                        row["sequence"],
                    ),
                )
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

    def pending_outbox(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("""SELECT sequence,command_id,status,result_json FROM agent_commands
                WHERE status IN ('succeeded','failed','indeterminate') AND uploaded_at IS NULL ORDER BY sequence""")
            return [{"sequence": row["sequence"], "command_id": row["command_id"], "status": row["status"],
                     "result": json.loads(row["result_json"])} for row in rows]

    def mark_uploaded(self, command_id: str) -> None:
        with self.connect() as db:
            changed = db.execute("""UPDATE agent_commands SET uploaded_at=?
                WHERE command_id=? AND status IN ('succeeded','failed','indeterminate')""",
                (int(time.time()), command_id)).rowcount
            if changed != 1:
                raise ProtocolError("outbox command is not complete")


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


class LocalMieruExecutor:
    """Typed adapter to the local authenticated Mieru manager; no caller supplied path/body."""

    def __init__(self, client):
        self.client = client

    async def execute(self, item: TypedCommand) -> dict:
        if item.operation == "mieru.inspect":
            data = await self.client.health()
            result = {"mieru_status": data.get("status"), "mieru_ready": data.get("ready"),
                      "mieru_revision": data.get("revision")}
        elif item.operation == "mieru.metrics":
            data = await self.client.metrics()
            result = {
                "metrics_status": data.get("status"),
                "metrics_stale": data.get("stale") is True,
                "metrics_capability": data.get("capability"),
                "metrics_reason": data.get("reason"),
            }
        elif item.operation in {
            "mieru.lifecycle.start",
            "mieru.lifecycle.stop",
            "mieru.lifecycle.restart",
        }:
            try:
                data = await self.client.lifecycle(item.operation.rsplit(".", 1)[1])
            except MieruError as exc:
                if exc.status_code >= 500:
                    raise ExecutionIndeterminate(
                        "Mieru lifecycle outcome requires reconciliation"
                    ) from exc
                raise ProtocolError("local Mieru manager rejected lifecycle command") from exc
            result = {
                "mieru_status": data.get("status"),
                "mieru_ready": data.get("ready"),
                "mieru_revision": data.get("revision"),
            }
        else:
            raise ProtocolError("Mieru operation is not executable without sealed payload support")
        return validate_result(result)


class RoutingExecutor:
    def __init__(self, *, telemt, mieru):
        self.telemt, self.mieru = telemt, mieru

    async def execute(self, item: TypedCommand) -> dict:
        if item.operation.startswith("mieru."):
            if self.mieru is None:
                raise ProtocolError("local Mieru manager is unavailable")
            return await self.mieru.execute(item)
        if self.telemt is None:
            raise ProtocolError("local Telemt manager is unavailable")
        return await self.telemt.execute(item)


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
        if item.expires_at <= int(time.time()):
            return self.journal.finish(item, "failed", {"message": "command rejected (ProtocolError)"})
        try:
            result = await self.executor.execute(item)
        except ExecutionIndeterminate:
            protocol = "Mieru" if item.operation.startswith("mieru.") else "Telemt"
            return self.journal.finish(
                item,
                "indeterminate",
                {"message": f"outcome requires {protocol} reconciliation"},
            )
        except Exception as exc:
            # Never persist exception text: third-party errors can contain headers/bodies.
            code = type(exc).__name__ if isinstance(exc, (ProtocolError, ValueError)) else "ExecutorError"
            return self.journal.finish(item, "failed", {"message": f"command rejected ({code})"})
        return self.journal.finish(item, "succeeded", result)


class AgentTransportClient:
    """Outbound-only WebPKI TLS client with a unique node certificate and durable upload retries."""

    def __init__(self, *, node_id: str, central_url: str, cert: Path, key: Path, agent: NodeAgent,
                 server_ca: Path | bool = True, request_timeout: float = 35):
        parts = urlsplit(central_url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ProtocolError("central_url must be an HTTPS origin")
        if node_id != agent.node_id:
            raise ProtocolError("transport node_id does not match agent")
        for path in (Path(cert), Path(key)):
            if not path.is_file():
                raise ProtocolError("agent certificate files are required")
        self.node_id, self.agent = node_id, agent
        verify_context = ssl.create_default_context(cafile=str(server_ca) if isinstance(server_ca, Path) else None)
        verify_context.minimum_version = ssl.TLSVersion.TLSv1_2
        verify_context.load_cert_chain(str(cert), str(key))
        self.client = httpx.AsyncClient(
            base_url=central_url.rstrip("/"), verify=verify_context,
            timeout=httpx.Timeout(request_timeout, connect=min(request_timeout, 10)), trust_env=False,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        )

    async def close(self):
        await self.client.aclose()

    async def upload_result(self, result: dict) -> None:
        command_id = result["command_id"]
        response = await self.client.put(
            f"/agent/v1/nodes/{self.node_id}/commands/{command_id}/result",
            json={key: result[key] for key in ("sequence", "status", "result")},
        )
        if len(response.content) > 65_536:
            raise ProtocolError("central response is too large")
        if response.status_code != 200:
            raise httpx.HTTPStatusError("central rejected result", request=response.request, response=response)
        self.agent.journal.mark_uploaded(command_id)

    async def run_once(self) -> bool:
        try:
            pending = self.agent.journal.pending_outbox()
            if pending:
                await self.upload_result(pending[0])
                return True
            response = await self.client.get(f"/agent/v1/nodes/{self.node_id}/commands/next")
            response.raise_for_status()
            if len(response.content) > 65_536:
                raise ProtocolError("central response is too large")
            command = response.json().get("command")
            if command is None:
                return True
            await self.upload_result(await self.agent.apply(command))
            return True
        except (httpx.HTTPError, ValueError, ProtocolError):
            return False

    async def run_forever(self, retry_min: float = 1, retry_max: float = 30):
        delay = retry_min
        while True:
            if await self.run_once():
                delay = retry_min
            else:
                await asyncio.sleep(delay)
                delay = min(retry_max, delay * 2)
