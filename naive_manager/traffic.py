from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable


MAX_COUNTER = 2**63 - 1


def _now() -> str:
    return datetime.now(UTC).isoformat()


class TrafficCollector:
    """Durably account complete Caddy CONNECT access-log records exactly once."""

    def __init__(
        self,
        log_path: Path,
        database_path: Path,
        managed_users: Callable[[], set[str]],
        *,
        max_line_bytes: int = 1024 * 1024,
        max_read_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self.log_path = Path(log_path)
        self.database_path = Path(database_path)
        self.managed_users = managed_users
        self.max_line_bytes = max_line_bytes
        self.max_read_bytes = max_read_bytes
        if self.max_line_bytes <= 0 or self.max_read_bytes <= self.max_line_bytes:
            raise ValueError("max_read_bytes must be greater than max_line_bytes")
        self._lock = threading.RLock()
        self._last_error: str | None = None
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
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
                PRIMARY KEY(device, inode)
            );
            CREATE TABLE IF NOT EXISTS traffic_counters (
                username TEXT PRIMARY KEY,
                upload_bytes INTEGER NOT NULL CHECK(upload_bytes >= 0),
                download_bytes INTEGER NOT NULL CHECK(download_bytes >= 0),
                period_start TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(traffic_files)")}
        if "discarding" not in columns:
            self._db.execute(
                "ALTER TABLE traffic_files ADD COLUMN discarding INTEGER NOT NULL DEFAULT 0 "
                "CHECK(discarding IN (0, 1))"
            )
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

    def _candidates(self) -> list[Path]:
        parent = self.log_path.parent
        try:
            entries = list(parent.iterdir())
        except OSError as exc:
            raise RuntimeError("accounting log directory unavailable") from exc
        candidates = [entry for entry in entries if entry.name == self.log_path.name or entry.name.startswith(self.log_path.name + ".")]
        if self.log_path not in candidates:
            raise RuntimeError("active accounting log is missing")
        # Process oldest rotations first and the active inode last. Identity+offset
        # keeps this ordering replay-safe across restart and rename rotation.
        return sorted(
            candidates,
            key=lambda value: (value == self.log_path, value.lstat().st_mtime_ns, value.name),
        )

    def collect(self) -> int:
        with self._lock:
            accepted = 0
            try:
                users = self.managed_users()
                if not isinstance(users, set) or any(not isinstance(value, str) for value in users):
                    raise RuntimeError("managed-user state unavailable")
                budget = self.max_read_bytes
                for path in self._candidates():
                    if budget <= 0:
                        break
                    count, consumed = self._collect_file(path, users, budget)
                    accepted += count
                    budget -= consumed
                self._last_error = None
                return accepted
            except Exception as exc:
                self._last_error = type(exc).__name__
                raise

    def _collect_file(self, path: Path, users: set[str], budget: int) -> tuple[int, int]:
        fd, info = self._open_regular(path)
        identity = (info.st_dev, info.st_ino)
        try:
            row = self._db.execute(
                "SELECT offset,tail_digest,discarding FROM traffic_files WHERE device=? AND inode=?", identity
            ).fetchone()
            offset = int(row[0]) if row else 0
            discarding = bool(row[2]) if row else False
            if row and offset:
                probe_start = max(0, offset - 64)
                os.lseek(fd, probe_start, os.SEEK_SET)
                actual_tail = hashlib.sha256(os.read(fd, offset - probe_start)).digest()
            else:
                actual_tail = None
            if info.st_size < offset or (row and row[1] is not None and actual_tail != row[1]):
                offset = 0
                discarding = False
            os.lseek(fd, offset, os.SEEK_SET)
            data = os.read(fd, min(budget, info.st_size - offset))

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
            tail_start = max(0, new_offset - 64)
            os.lseek(fd, tail_start, os.SEEK_SET)
            tail_digest = hashlib.sha256(os.read(fd, new_offset - tail_start)).digest()
        finally:
            os.close(fd)

        accepted = 0
        increments: dict[str, tuple[int, int]] = {}
        existing_totals: dict[str, tuple[int, int]] = {}
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
            ):
                continue
            increments[username] = (prior[0] + upload, prior[1] + download)
            accepted += 1
        now = _now()
        with self._db:
            self._db.execute(
                "INSERT INTO traffic_files(device,inode,offset,path,tail_digest,discarding) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(device,inode) DO UPDATE SET "
                "offset=excluded.offset,path=excluded.path,tail_digest=excluded.tail_digest,"
                "discarding=excluded.discarding",
                (*identity, new_offset, str(path), tail_digest, int(discarding)),
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
        return accepted, len(data)

    def _parse(self, raw: bytes, users: set[str]) -> tuple[str, int, int] | None:
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
            or username.casefold().startswith("invalid")
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
            for path in self._candidates():
                fd, info = self._open_regular(path)
                try:
                    identity = (info.st_dev, info.st_ino)
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

    def list_traffic(self) -> dict:
        with self._lock:
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

    def reset(self, username: str) -> dict:
        users = self.managed_users()
        if username not in users:
            raise KeyError(username)
        now = _now()
        with self._lock, self._db:
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
            "period_start": now,
            "updated_at": now,
        }

    def health(self) -> dict:
        try:
            fd, _info = self._open_regular(self.log_path)
            os.close(fd)
            ready = self._last_error is None
        except RuntimeError:
            ready = False
        return {"ready": ready, "source": "caddy_connect_access_log", "error": self._last_error}
