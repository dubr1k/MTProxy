from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Set as AbstractSet
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable


MAX_COUNTER = 2**63 - 1
REDACTION_SENTINEL = "invalid"


@dataclass(frozen=True)
class _Candidate:
    path: Path
    identity: tuple[int, int]
    active: bool


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _assert_safe_parent_chain(path: Path) -> None:
    parent = path.absolute().parent
    for directory in reversed(parent.parents):
        if directory == directory.parent:
            continue
        try:
            info = directory.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("accounting path parent is unsafe")
    try:
        info = parent.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("accounting path parent is unsafe")


class TrafficCollector:
    """Durably account complete Caddy CONNECT access-log records exactly once."""

    def __init__(
        self,
        log_path: Path,
        database_path: Path,
        managed_users: Callable[[], set[str]],
        *,
        max_line_bytes: int = 1024 * 1024,
        max_read_bytes: int = 32 * 1024 * 1024,
        max_verify_bytes: int = 16 * 1024 * 1024,
        max_drain_rounds: int = 16,
        max_rotations: int = 10,
        max_directory_entries: int = 4096,
    ) -> None:
        self.log_path = Path(log_path)
        self.database_path = Path(database_path)
        self.managed_users = managed_users
        self.max_line_bytes = max_line_bytes
        self.max_read_bytes = max_read_bytes
        self.max_verify_bytes = max_verify_bytes
        self.max_drain_rounds = max_drain_rounds
        self.max_rotations = max_rotations
        self.max_directory_entries = max_directory_entries
        if (
            self.max_line_bytes <= 0
            or self.max_read_bytes <= self.max_line_bytes
            or self.max_verify_bytes <= 0
        ):
            raise ValueError("max_read_bytes must be greater than max_line_bytes")
        if self.max_drain_rounds <= 0:
            raise ValueError("max_drain_rounds must be positive")
        if self.max_rotations < 0 or self.max_directory_entries <= self.max_rotations:
            raise ValueError("invalid accounting directory bounds")
        self._lock = threading.RLock()
        self._operation_lock = threading.RLock()
        self._last_error: str | None = None
        _assert_safe_parent_chain(self.log_path)
        _assert_safe_parent_chain(self.database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        _assert_safe_parent_chain(self.database_path)
        if self.database_path.is_symlink():
            raise RuntimeError("accounting database is unsafe")
        if self.database_path.exists():
            database_info = self.database_path.lstat()
            if not stat.S_ISREG(database_info.st_mode):
                raise RuntimeError("accounting database is unsafe")
        else:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.database_path, flags, 0o600)
            os.close(fd)
        self._db = sqlite3.connect(self.database_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS traffic_files (
                device INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL CHECK(offset >= 0),
                path TEXT NOT NULL,
                tail_digest BLOB,
                discarding INTEGER NOT NULL DEFAULT 0 CHECK(discarding IN (0, 1)),
                observed_mtime_ns INTEGER,
                observed_ctime_ns INTEGER,
                file_size INTEGER,
                observed_head_digest BLOB,
                observed_tail_digest BLOB,
                consumed_prefix_digest BLOB,
                PRIMARY KEY(device, inode)
            );
            CREATE TABLE IF NOT EXISTS traffic_counters (
                username TEXT PRIMARY KEY,
                upload_bytes INTEGER NOT NULL CHECK(upload_bytes >= 0),
                download_bytes INTEGER NOT NULL CHECK(download_bytes >= 0),
                period_start TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_archives (
                username TEXT PRIMARY KEY,
                upload_bytes INTEGER NOT NULL CHECK(upload_bytes >= 0),
                download_bytes INTEGER NOT NULL CHECK(download_bytes >= 0),
                period_start TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                archived_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounting_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                error TEXT NOT NULL,
                detected_at TEXT NOT NULL
            );
            """
        )
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(traffic_files)")}
        if "discarding" not in columns:
            self._db.execute(
                "ALTER TABLE traffic_files ADD COLUMN discarding INTEGER NOT NULL DEFAULT 0 "
                "CHECK(discarding IN (0, 1))"
            )
        if "observed_mtime_ns" not in columns:
            self._db.execute("ALTER TABLE traffic_files ADD COLUMN observed_mtime_ns INTEGER")
        if "observed_ctime_ns" not in columns:
            self._db.execute("ALTER TABLE traffic_files ADD COLUMN observed_ctime_ns INTEGER")
        if "file_size" not in columns:
            self._db.execute("ALTER TABLE traffic_files ADD COLUMN file_size INTEGER")
        if "observed_head_digest" not in columns:
            self._db.execute("ALTER TABLE traffic_files ADD COLUMN observed_head_digest BLOB")
        if "observed_tail_digest" not in columns:
            self._db.execute("ALTER TABLE traffic_files ADD COLUMN observed_tail_digest BLOB")
        if "consumed_prefix_digest" not in columns:
            self._db.execute("ALTER TABLE traffic_files ADD COLUMN consumed_prefix_digest BLOB")
        self._db.commit()
        self._secure_database_files()

    def _secure_database_files(self) -> None:
        for path in (
            self.database_path,
            Path(str(self.database_path) + "-wal"),
            Path(str(self.database_path) + "-shm"),
        ):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise RuntimeError("accounting database is unsafe")
            os.chmod(path, 0o600)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _assert_accounting_ready(self) -> None:
        row = self._db.execute("SELECT error FROM accounting_state WHERE singleton=1").fetchone()
        if row is not None:
            raise RuntimeError("persistent accounting loss requires operator recovery")

    @contextmanager
    def operation(self):
        """Serialize lifecycle mutations with snapshots and accounting commits."""
        with self._operation_lock:
            yield

    @staticmethod
    def _open_regular(path: Path) -> tuple[int, os.stat_result]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise RuntimeError("accounting log unavailable or unsafe") from exc
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise RuntimeError("accounting log is not a regular file")
        return fd, info

    @staticmethod
    def _hash_prefix(fd: int, length: int) -> hashlib._Hash:
        digest = hashlib.sha256()
        cursor = 0
        while cursor < length:
            chunk = os.pread(fd, min(64 * 1024, length - cursor), cursor)
            if not chunk:
                raise RuntimeError("accounting log changed while being inspected")
            digest.update(chunk)
            cursor += len(chunk)
        return digest

    def _candidates(self) -> list[_Candidate]:
        parent = self.log_path.parent
        rotation = self._rotation_matcher()
        try:
            candidates: dict[tuple[int, int], _Candidate] = {}
            with os.scandir(parent) as entries:
                for scanned, entry in enumerate(entries, 1):
                    if scanned > self.max_directory_entries:
                        raise RuntimeError("accounting log directory entry limit exceeded")
                    if entry.name == self.log_path.name or rotation.fullmatch(entry.name):
                        path = Path(entry.path)
                        fd, info = self._open_regular(path)
                        os.close(fd)
                        if entry.inode() != info.st_ino:
                            raise RuntimeError("accounting log changed during discovery")
                        candidate = _Candidate(
                            path=path,
                            identity=(info.st_dev, info.st_ino),
                            active=entry.name == self.log_path.name,
                        )
                        existing = candidates.get(candidate.identity)
                        if (
                            existing is None
                            or candidate.active
                            or (not existing.active and path.name < existing.path.name)
                        ):
                            candidates[candidate.identity] = candidate
                        if len(candidates) > self.max_rotations + 1:
                            raise RuntimeError("accounting log rotation limit exceeded")
        except OSError as exc:
            raise RuntimeError("accounting log directory unavailable") from exc
        if not any(candidate.active for candidate in candidates.values()):
            raise RuntimeError("active accounting log is missing")
        # Process oldest rotations first and the active inode last. Identity+offset
        # keeps this ordering replay-safe across restart and rename rotation.
        return sorted(candidates.values(), key=lambda value: (value.active, value.path.name))

    def _rotation_matcher(self) -> re.Pattern[str]:
        suffix = self.log_path.suffix
        stem = self.log_path.name.removesuffix(suffix) if suffix else self.log_path.name
        return re.compile(
            rf"{re.escape(stem)}-\d{{4}}-\d{{2}}-\d{{2}}T"
            rf"\d{{2}}-\d{{2}}-\d{{2}}\.\d{{3}}-(?:size|rotate){re.escape(suffix)}\Z"
        )

    def _present_identities(self) -> set[tuple[int, int]]:
        """Rescan and open current names so stale discovery paths cannot drive pruning."""
        parent = self.log_path.parent
        rotation = self._rotation_matcher()
        present = set()
        active_seen = False
        try:
            with os.scandir(parent) as entries:
                for scanned, entry in enumerate(entries, 1):
                    if scanned > self.max_directory_entries:
                        raise RuntimeError("accounting log directory entry limit exceeded")
                    if entry.name == self.log_path.name or rotation.fullmatch(entry.name):
                        fd, info = self._open_regular(Path(entry.path))
                        os.close(fd)
                        if entry.inode() != info.st_ino:
                            raise RuntimeError("accounting log changed during discovery")
                        present.add((info.st_dev, info.st_ino))
                        if len(present) > self.max_rotations + 1:
                            raise RuntimeError("accounting log rotation limit exceeded")
                        active_seen = active_seen or entry.name == self.log_path.name
        except OSError as exc:
            raise RuntimeError("accounting log directory unavailable") from exc
        if not active_seen:
            raise RuntimeError("active accounting log is missing")
        return present

    def collect(self) -> int:
        with self.operation():
            users = self.managed_users()
            if not isinstance(users, set) or any(not isinstance(value, str) for value in users):
                raise RuntimeError("managed-user state unavailable")
            users = frozenset(users)
            return self._collect_locked(users)

    def _collect_locked(self, users: AbstractSet[str]) -> int:
        with self._lock:
            accepted = 0
            try:
                self._assert_accounting_ready()
                budget = self.max_read_bytes
                verify_budget = self.max_verify_bytes
                candidates = self._candidates()
                for candidate in candidates:
                    count, consumed, verified = self._collect_file(
                        candidate, users, budget, verify_budget,
                    )
                    accepted += count
                    budget -= consumed
                    verify_budget -= verified
                self._prune_consumed_deleted()
                self._last_error = None
                return accepted
            except Exception as exc:
                self._last_error = type(exc).__name__
                raise

    def _collect_file(
        self, candidate: _Candidate, users: AbstractSet[str], budget: int, verify_budget: int,
    ) -> tuple[int, int, int]:
        path = candidate.path
        fd, info = self._open_regular(path)
        identity = (info.st_dev, info.st_ino)
        try:
            if identity != candidate.identity:
                raise RuntimeError("accounting log changed during discovery")
            row = self._db.execute(
                "SELECT offset,discarding,consumed_prefix_digest "
                "FROM traffic_files WHERE device=? AND inode=?", identity
            ).fetchone()
            offset = int(row[0]) if row else 0
            discarding = bool(row[1]) if row else False
            if info.st_size < offset:
                raise RuntimeError("accounting log violates rename-only rotation contract")
            if row and offset and row[2] is None:
                raise RuntimeError("accounting prefix cannot be verified after schema upgrade")
            available = info.st_size - offset
            if row and offset > verify_budget:
                raise RuntimeError("accounting prefix verification budget exceeded")
            prefix = self._hash_prefix(fd, offset)
            if row and prefix.digest() != row[2]:
                raise RuntimeError("accounting log violates rename-only rotation contract")
            data = b"" if budget <= 0 else os.pread(fd, min(budget, available), offset)

            cursor = 0
            processed_end = 0
            if discarding:
                newline = data.find(b"\n")
                if newline < 0:
                    processed_end = len(data)
                else:
                    cursor = newline + 1
                    processed_end = cursor
                    discarding = False

            remaining = data[cursor:]
            complete_end = remaining.rfind(b"\n") + 1
            complete = remaining[:complete_end]
            if complete_end:
                processed_end = cursor + complete_end
            trailing = len(remaining) - complete_end
            if trailing > self.max_line_bytes:
                # Persist bounded discard progress. Otherwise one malformed record
                # larger than max_read_bytes would pin this inode forever.
                processed_end = len(data)
                discarding = True

            new_offset = offset + processed_end
            prefix.update(data[:processed_end])
            consumed_prefix_digest = prefix.digest()
        finally:
            os.close(fd)

        accepted = 0
        increments: dict[str, tuple[int, int]] = {}
        existing_totals: dict[str, tuple[int, int]] = {}
        global_total = sum(
            int(upload) + int(download)
            for upload, download in self._db.execute(
                "SELECT upload_bytes,download_bytes FROM traffic_counters"
            ).fetchall()
        )
        pending_global = 0
        for raw in complete.splitlines():
            parsed = self._parse(raw, users)
            if parsed is None:
                continue
            username, upload, download = parsed
            prior = increments.get(username, (0, 0))
            if username not in existing_totals:
                existing = self._db.execute(
                    "SELECT upload_bytes,download_bytes FROM traffic_counters WHERE username=?",
                    (username,),
                ).fetchone()
                existing_totals[username] = tuple(existing) if existing else (0, 0)
            base = existing_totals[username]
            if (
                base[0] > MAX_COUNTER - prior[0] - upload
                or base[1] > MAX_COUNTER - prior[1] - download
                or base[0] + base[1] > MAX_COUNTER - prior[0] - prior[1] - upload - download
                or global_total > MAX_COUNTER - pending_global - upload - download
            ):
                continue
            increments[username] = (prior[0] + upload, prior[1] + download)
            pending_global += upload + download
            accepted += 1
        now = _now()
        with self._db:
            self._db.execute(
                "INSERT INTO traffic_files(device,inode,offset,path,tail_digest,discarding,"
                "observed_mtime_ns,observed_ctime_ns,file_size,observed_head_digest,"
                "observed_tail_digest,consumed_prefix_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(device,inode) DO UPDATE SET "
                "offset=excluded.offset,path=excluded.path,tail_digest=excluded.tail_digest,"
                "discarding=excluded.discarding,observed_mtime_ns=excluded.observed_mtime_ns,"
                "observed_ctime_ns=excluded.observed_ctime_ns,file_size=excluded.file_size,"
                "observed_head_digest=excluded.observed_head_digest,"
                "observed_tail_digest=excluded.observed_tail_digest,"
                "consumed_prefix_digest=excluded.consumed_prefix_digest",
                (
                    *identity, new_offset, str(path), None, int(discarding),
                    info.st_mtime_ns, info.st_ctime_ns, info.st_size,
                    None, None, consumed_prefix_digest,
                ),
            )
            for username, (upload, download) in increments.items():
                self._db.execute(
                    "INSERT INTO traffic_counters(username,upload_bytes,download_bytes,period_start,updated_at) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET "
                    "upload_bytes=upload_bytes+excluded.upload_bytes,"
                    "download_bytes=download_bytes+excluded.download_bytes,updated_at=excluded.updated_at",
                    (username, upload, download, now, now),
                )
        self._secure_database_files()
        return accepted, len(data), offset

    def _prune_consumed_deleted(self) -> None:
        present = self._present_identities()
        loss_detected = False
        with self._db:
            for device, inode, offset, size, discarding in self._db.execute(
                "SELECT device,inode,offset,file_size,discarding FROM traffic_files"
            ).fetchall():
                if (device, inode) not in present:
                    safely_consumed = (
                        size is not None and int(offset) == int(size) and not discarding
                    )
                    if not safely_consumed:
                        loss_detected = True
                        self._db.execute(
                            "INSERT INTO accounting_state(singleton,error,detected_at) VALUES(1,?,?) "
                            "ON CONFLICT(singleton) DO NOTHING",
                            ("accounting_loss", _now()),
                        )
                    self._db.execute(
                        "DELETE FROM traffic_files WHERE device=? AND inode=?", (device, inode)
                    )
        if loss_detected:
            raise RuntimeError("persistent accounting loss detected")

    def _parse(self, raw: bytes, users: AbstractSet[str]) -> tuple[str, int, int] | None:
        if not raw or len(raw) > self.max_line_bytes:
            return None
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict) or set(("request", "status", "user_id", "bytes_read", "size")) - value.keys():
            return None
        request = value["request"]
        username = value["user_id"]
        upload = value["bytes_read"]
        download = value["size"]
        if (
            not isinstance(request, dict)
            or request.get("method") != "CONNECT"
            or type(value["status"]) is not int
            or value["status"] < 200
            or value["status"] >= 300
            or not isinstance(username, str)
            or username not in users
            or username == REDACTION_SENTINEL
            or type(upload) is not int
            or type(download) is not int
            or not 0 <= upload <= MAX_COUNTER
            or not 0 <= download <= MAX_COUNTER
            or upload > MAX_COUNTER - download
        ):
            return None
        return username, upload, download

    def _pending(self) -> bool:
        try:
            for candidate in self._candidates():
                fd, info = self._open_regular(candidate.path)
                try:
                    identity = (info.st_dev, info.st_ino)
                    if identity != candidate.identity:
                        raise RuntimeError("accounting log changed during discovery")
                    row = self._db.execute(
                        "SELECT offset FROM traffic_files WHERE device=? AND inode=?", identity
                    ).fetchone()
                    offset = min(int(row[0]), info.st_size) if row else 0
                    if info.st_size > offset:
                        return True
                finally:
                    os.close(fd)
            return False
        except (OSError, RuntimeError):
            return True

    def drain(self) -> bool:
        for _ in range(self.max_drain_rounds):
            self.collect()
            with self._lock:
                if not self._pending():
                    return True
        return False

    def list_traffic(self) -> dict:
        with self._lock:
            self._assert_accounting_ready()
            rows = self._db.execute(
                "SELECT username,upload_bytes,download_bytes,period_start,updated_at "
                "FROM traffic_counters ORDER BY username"
            ).fetchall()
            users = [
                {
                    "username": username,
                    "upload_bytes": upload,
                    "download_bytes": download,
                    "total_bytes": upload + download,
                    "upload_bytes_decimal": str(upload),
                    "download_bytes_decimal": str(download),
                    "total_bytes_decimal": str(upload + download),
                    "period_start": period_start,
                    "updated_at": updated_at,
                }
                for username, upload, download, period_start, updated_at in rows
            ]
            aggregate = {
                "upload_bytes": sum(row["upload_bytes"] for row in users),
                "download_bytes": sum(row["download_bytes"] for row in users),
                "total_bytes": sum(row["total_bytes"] for row in users),
            }
            if aggregate["total_bytes"] > MAX_COUNTER:
                raise RuntimeError("accounting counter invariant violated")
            aggregate = {
                **aggregate,
                "upload_bytes_decimal": str(aggregate["upload_bytes"]),
                "download_bytes_decimal": str(aggregate["download_bytes"]),
                "total_bytes_decimal": str(aggregate["total_bytes"]),
            }
            return {
                "source": "caddy_connect_access_log",
                "unit": "bytes",
                "directions": {
                    "upload_bytes": "client_to_proxy",
                    "download_bytes": "proxy_to_client",
                },
                "aggregate": aggregate,
                "users": users,
                "pending": self._pending(),
                "semantics": {
                    "closed_connect_tunnels_only": True,
                    "active_tunnels_appear_on_close": True,
                    "crash_can_lose_active_tunnel": True,
                    "completed_records_survive_restart": True,
                    "excludes_tls_ip_overhead": True,
                    "reset_is_local_baseline_only": True,
                },
            }

    def archive_user(self, username: str) -> None:
        now = _now()
        with self.operation(), self._lock, self._db:
            self._assert_accounting_ready()
            row = self._db.execute(
                "SELECT upload_bytes,download_bytes,period_start,updated_at "
                "FROM traffic_counters WHERE username=?", (username,),
            ).fetchone()
            if row is not None:
                self._db.execute(
                    "INSERT INTO traffic_archives(username,upload_bytes,download_bytes,period_start,"
                    "updated_at,archived_at) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(username) DO NOTHING",
                    (username, *row, now),
                )
                self._db.execute("DELETE FROM traffic_counters WHERE username=?", (username,))
        self._secure_database_files()

    def reset(self, username: str) -> dict:
        now = _now()
        with self.operation(), self._lock, self._db:
            self._assert_accounting_ready()
            users = self.managed_users()
            if username not in users:
                raise KeyError(username)
            self._db.execute(
                "INSERT INTO traffic_counters(username,upload_bytes,download_bytes,period_start,updated_at) "
                "VALUES(?,0,0,?,?) ON CONFLICT(username) DO UPDATE SET "
                "upload_bytes=0,download_bytes=0,period_start=excluded.period_start,updated_at=excluded.updated_at",
                (username, now, now),
            )
        return {
            "username": username,
            "upload_bytes": 0,
            "download_bytes": 0,
            "total_bytes": 0,
            "upload_bytes_decimal": "0",
            "download_bytes_decimal": "0",
            "total_bytes_decimal": "0",
            "period_start": now,
            "updated_at": now,
        }

    def health(self) -> dict:
        try:
            with self._lock:
                self._assert_accounting_ready()
                fd, _info = self._open_regular(self.log_path)
                os.close(fd)
                ready = self._last_error is None
        except RuntimeError:
            ready = False
        return {"ready": ready, "source": "caddy_connect_access_log", "error": self._last_error}
