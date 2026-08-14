"""Typed, secret-free fleet protocol and durable central command registry.

This module intentionally contains no agent HTTP transport.  The panel can prepare and
inspect commands, but nodes cannot poll it until an authenticated mTLS transport is
implemented.  This keeps the protocol useful and testable without silently accepting a
weaker bearer-token boundary.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROTOCOL_VERSION = 1
NODE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
REVISION_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
FORBIDDEN_KEYS = {"secret", "password", "token", "authorization", "link", "links", "proxy_url", "api_token", "credential"}
INVENTORY_KEYS = {"agent_version", "telemt_version", "region", "hostname", "platform", "capabilities"}
OPERATIONS = {
    "telemt.inventory.refresh",
    "telemt.user.enable",
    "telemt.user.disable",
    "telemt.user.update_limits",
    "telemt.user.reset_quota",
}
LIMIT_FIELDS = {
    "data_quota_bytes": (1, 2**63 - 1),
    "rate_limit_up_bps": (1, 10**12),
    "rate_limit_down_bps": (1, 10**12),
    "max_tcp_conns": (1, 100_000),
    "max_unique_ips": (1, 100_000),
}


class ProtocolError(ValueError):
    pass


class CommandConflict(RuntimeError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _walk_secret_free(value: Any, path: str = "value") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ProtocolError(f"{path} contains a non-string key")
            normalized = key.casefold().replace("-", "_")
            if normalized in FORBIDDEN_KEYS or any(part in normalized for part in ("secret", "password", "token", "credential")):
                raise ProtocolError(f"{path} is secret-bearing")
            _walk_secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        if len(value) > 1000:
            raise ProtocolError(f"{path} is too large")
        for index, child in enumerate(value):
            _walk_secret_free(child, f"{path}[{index}]")
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ProtocolError(f"{path} contains an unsupported value")
    elif isinstance(value, str) and len(value) > 2048:
        raise ProtocolError(f"{path} is too large")


def validate_inventory(value: Any) -> dict:
    _walk_secret_free(value, "inventory")
    if not isinstance(value, dict) or set(value) - INVENTORY_KEYS:
        raise ProtocolError("inventory contains unsupported fields")
    if "capabilities" in value:
        capabilities = value["capabilities"]
        if not isinstance(capabilities, list) or any(item not in OPERATIONS for item in capabilities):
            raise ProtocolError("inventory capabilities are invalid")
    for key in set(value) - {"capabilities"}:
        if not isinstance(value[key], str) or not value[key] or len(value[key]) > 128:
            raise ProtocolError(f"inventory {key} is invalid")
    return value


def validate_payload(operation: str, payload: Any) -> dict:
    _walk_secret_free(payload, "payload")
    if not isinstance(payload, dict):
        raise ProtocolError("payload must be an object")
    if operation == "telemt.inventory.refresh":
        if payload:
            raise ProtocolError("payload must be empty")
        return payload
    allowed = {"username"} | (set(LIMIT_FIELDS) if operation == "telemt.user.update_limits" else set())
    if set(payload) - allowed or set(payload) < {"username"}:
        raise ProtocolError("payload fields are invalid")
    if not isinstance(payload["username"], str) or not USER_RE.fullmatch(payload["username"]):
        raise ProtocolError("payload username is invalid")
    if operation == "telemt.user.update_limits":
        if set(payload) == {"username"}:
            raise ProtocolError("payload requires at least one limit")
        for key in set(payload) - {"username"}:
            value = payload[key]
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not LIMIT_FIELDS[key][0] <= value <= LIMIT_FIELDS[key][1]):
                raise ProtocolError(f"payload {key} is invalid")
    return payload


def validate_result(value: Any, operation: str | None = None, status: str | None = None) -> dict:
    _walk_secret_free(value, "result")
    if not isinstance(value, dict):
        raise ProtocolError("result must be an object")
    allowed = {"username", "enabled", "used_bytes", "telemt_revision", "inventory", "message"}
    if set(value) - allowed:
        raise ProtocolError("result contains unsupported fields")
    if "username" in value and (not isinstance(value["username"], str) or not USER_RE.fullmatch(value["username"])):
        raise ProtocolError("result username is invalid")
    if "enabled" in value and not isinstance(value["enabled"], bool):
        raise ProtocolError("result enabled is invalid")
    if "used_bytes" in value and (isinstance(value["used_bytes"], bool) or not isinstance(value["used_bytes"], int) or value["used_bytes"] < 0):
        raise ProtocolError("result used_bytes is invalid")
    if "telemt_revision" in value and (not isinstance(value["telemt_revision"], str) or not REVISION_RE.fullmatch(value["telemt_revision"])):
        raise ProtocolError("result telemt_revision is invalid")
    if "message" in value and value["message"] not in {
        "outcome requires Telemt reconciliation", "command rejected (ProtocolError)",
        "command rejected (ValueError)", "command rejected (ExecutorError)",
    }:
        raise ProtocolError("result message is invalid")
    if "inventory" in value:
        validate_inventory(value["inventory"])
    if status in {"failed", "indeterminate"} and set(value) != {"message"}:
        raise ProtocolError("failure result is invalid")
    if status == "succeeded" and operation:
        if operation == "telemt.inventory.refresh":
            if set(value) != {"inventory", "telemt_revision"}:
                raise ProtocolError("inventory result is invalid")
        elif not {"username", "telemt_revision"} <= set(value) or "inventory" in value or "message" in value:
            raise ProtocolError("user operation result is invalid")
    return value


@dataclass(frozen=True)
class TypedCommand:
    protocol_version: int
    command_id: str
    node_id: str
    sequence: int
    idempotency_key: str
    operation: str
    expected_telemt_revision: str
    payload: dict

    @classmethod
    def parse(cls, raw: Any) -> "TypedCommand":
        if not isinstance(raw, dict) or set(raw) != {
            "protocol_version", "command_id", "node_id", "sequence", "idempotency_key",
            "operation", "expected_telemt_revision", "payload",
        }:
            raise ProtocolError("command envelope fields are invalid")
        if raw["protocol_version"] != PROTOCOL_VERSION:
            raise ProtocolError("protocol_version is unsupported")
        try:
            uuid.UUID(raw["command_id"])
        except (ValueError, TypeError, AttributeError) as exc:
            raise ProtocolError("command_id is invalid") from exc
        if not isinstance(raw["node_id"], str) or not NODE_RE.fullmatch(raw["node_id"]):
            raise ProtocolError("node_id is invalid")
        if isinstance(raw["sequence"], bool) or not isinstance(raw["sequence"], int) or raw["sequence"] < 1:
            raise ProtocolError("sequence is invalid")
        if not isinstance(raw["idempotency_key"], str) or not KEY_RE.fullmatch(raw["idempotency_key"]):
            raise ProtocolError("idempotency_key is invalid")
        if raw["operation"] not in OPERATIONS:
            raise ProtocolError("operation is not allowlisted")
        if not isinstance(raw["expected_telemt_revision"], str) or not REVISION_RE.fullmatch(raw["expected_telemt_revision"]):
            raise ProtocolError("expected_telemt_revision is invalid")
        payload = validate_payload(raw["operation"], raw["payload"])
        return cls(**{**raw, "payload": payload})

    def as_dict(self) -> dict:
        return {
            "protocol_version": self.protocol_version, "command_id": self.command_id,
            "node_id": self.node_id, "sequence": self.sequence,
            "idempotency_key": self.idempotency_key, "operation": self.operation,
            "expected_telemt_revision": self.expected_telemt_revision, "payload": self.payload,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.as_dict()).encode()).hexdigest()


class FleetStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
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
            CREATE TABLE IF NOT EXISTS fleet_nodes (
              node_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, auth_state TEXT NOT NULL,
              inventory_json TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
              next_sequence INTEGER NOT NULL DEFAULT 1, last_result_sequence INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS fleet_commands (
              command_id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE RESTRICT,
              sequence INTEGER NOT NULL, idempotency_key TEXT NOT NULL, protocol_version INTEGER NOT NULL,
              operation TEXT NOT NULL, expected_revision TEXT NOT NULL, payload_json TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('queued','succeeded','failed','indeterminate')),
              result_json TEXT, created_at INTEGER NOT NULL, completed_at INTEGER,
              UNIQUE(node_id,sequence), UNIQUE(node_id,idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS fleet_commands_node_sequence ON fleet_commands(node_id,sequence);
            """)

    def register_node(self, node_id: str, display_name: str, inventory: dict) -> dict:
        if not NODE_RE.fullmatch(node_id):
            raise ProtocolError("node_id is invalid")
        if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 128:
            raise ProtocolError("display_name is invalid")
        inventory = validate_inventory(inventory)
        now = int(time.time())
        with self.connect() as db:
            db.execute("""INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)
                VALUES(?,?,'network_disabled',?,?,?)""", (node_id, display_name.strip(), _canonical(inventory), now, now))
        return self.node(node_id)

    def node(self, node_id: str) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT * FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone()
        if not row:
            raise KeyError(node_id)
        return self._node(row)

    def nodes(self) -> list[dict]:
        with self.connect() as db:
            return [self._node(row) for row in db.execute("SELECT * FROM fleet_nodes ORDER BY node_id")]

    @staticmethod
    def _node(row) -> dict:
        value = dict(row)
        value["inventory"] = json.loads(value.pop("inventory_json"))
        return value

    def enqueue(self, node_id: str, idempotency_key: str, operation: str, payload: dict, expected_revision: str) -> dict:
        if not KEY_RE.fullmatch(idempotency_key or ""):
            raise ProtocolError("idempotency_key is invalid")
        if operation not in OPERATIONS:
            raise ProtocolError("operation is not allowlisted")
        payload = validate_payload(operation, payload)
        if not REVISION_RE.fullmatch(expected_revision or ""):
            raise ProtocolError("expected_telemt_revision is invalid")
        canonical_payload = _canonical(payload)
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT * FROM fleet_commands WHERE node_id=? AND idempotency_key=?", (node_id, idempotency_key)).fetchone()
            if previous:
                if (previous["operation"], previous["payload_json"], previous["expected_revision"]) != (operation, canonical_payload, expected_revision):
                    raise CommandConflict("idempotency key was reused with different command data")
                return self._command(previous)
            node = db.execute("SELECT next_sequence FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone()
            if not node:
                raise KeyError(node_id)
            sequence = node["next_sequence"]
            raw = {
                "protocol_version": PROTOCOL_VERSION, "command_id": str(uuid.uuid4()), "node_id": node_id,
                "sequence": sequence, "idempotency_key": idempotency_key, "operation": operation,
                "expected_telemt_revision": expected_revision, "payload": payload,
            }
            item = TypedCommand.parse(raw)
            now = int(time.time())
            db.execute("""INSERT INTO fleet_commands(command_id,node_id,sequence,idempotency_key,protocol_version,operation,
                expected_revision,payload_json,status,created_at) VALUES(?,?,?,?,?,?,?,?, 'queued',?)""",
                (item.command_id, node_id, sequence, idempotency_key, PROTOCOL_VERSION, operation, expected_revision, canonical_payload, now))
            db.execute("UPDATE fleet_nodes SET next_sequence=next_sequence+1,updated_at=? WHERE node_id=?", (now, node_id))
            row = db.execute("SELECT * FROM fleet_commands WHERE command_id=?", (item.command_id,)).fetchone()
            return self._command(row)

    def commands(self, node_id: str) -> list[dict]:
        with self.connect() as db:
            return [self._command(row) for row in db.execute("SELECT * FROM fleet_commands WHERE node_id=? ORDER BY sequence", (node_id,))]

    def record_result(self, node_id: str, command_id: str, sequence: int, status: str, result: dict) -> dict:
        if status not in {"succeeded", "failed", "indeterminate"}:
            raise ProtocolError("result status is invalid")
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM fleet_commands WHERE command_id=? AND node_id=? AND sequence=?", (command_id, node_id, sequence)).fetchone()
            if not row:
                raise KeyError(command_id)
            result = validate_result(result, row["operation"], status)
            canonical_result = _canonical(result)
            if row["status"] != "queued":
                if row["status"] == status and row["result_json"] == canonical_result:
                    return self._command(row)
                raise CommandConflict("result replay does not match stored outcome")
            node = db.execute("SELECT last_result_sequence FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone()
            if sequence != node["last_result_sequence"] + 1:
                raise ProtocolError("result sequence gap")
            db.execute("UPDATE fleet_commands SET status=?,result_json=?,completed_at=? WHERE command_id=?", (status, canonical_result, int(time.time()), command_id))
            db.execute("UPDATE fleet_nodes SET last_result_sequence=?,updated_at=? WHERE node_id=?", (sequence, int(time.time()), node_id))
            return self._command(db.execute("SELECT * FROM fleet_commands WHERE command_id=?", (command_id,)).fetchone())

    @staticmethod
    def _command(row) -> dict:
        value = dict(row)
        value["expected_telemt_revision"] = value.pop("expected_revision")
        value["payload"] = json.loads(value.pop("payload_json"))
        value["result"] = json.loads(value.pop("result_json")) if value.get("result_json") else None
        return value
