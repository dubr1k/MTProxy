from __future__ import annotations

import copy
import functools
import json
import os
import re
import secrets
import stat
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable
from urllib.parse import quote

from .traffic import (
    ACCOUNTING_ROLL_KEEP,
    ACCOUNTING_ROLL_SIZE_BYTES,
    MAX_COUNTER,
    REDACTION_SENTINEL,
    TrafficCollector,
)


BEGIN = "# BEGIN NAIVE-MANAGER USERS"
END = "# END NAIVE-MANAGER USERS"
ACCOUNTING_BEGIN = "# BEGIN NAIVE-MANAGER ACCOUNTING"
ACCOUNTING_END = "# END NAIVE-MANAGER ACCOUNTING"
USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
DISABLED_REASONS = {None, "manual", "quota"}


def synchronized(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped


def lifecycle_synchronized(method):
    """Acquire the accounting operation boundary before manager state."""
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        traffic = self.traffic
        if traffic is None:
            with self._lock:
                return method(self, *args, **kwargs)
        with traffic.operation(), self._lock:
            return method(self, *args, **kwargs)
    return wrapped


class ManagerConflict(RuntimeError):
    """A refused operation. `code` names the reason for callers to act on."""

    def __init__(self, message: str, code: str = "configuration_conflict"):
        super().__init__(message)
        self.code = code


class ManagerNotFound(RuntimeError):
    pass


class ManagerRecoveryError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _fsync_directory(path: Path) -> None:
    directory = os.open(path, os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _durable_mkdir(path: Path, mode: int = 0o700) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise ManagerConflict(f"refusing unsafe directory: {current}")
    for directory in reversed(missing):
        os.mkdir(directory, mode)
        _fsync_directory(directory.parent)


def _assert_safe_parent_chain(path: Path) -> None:
    parent = path.absolute().parent
    for directory in (*reversed(parent.parents), parent):
        if directory == directory.parent:
            continue
        try:
            info = directory.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ManagerConflict(f"refusing unsafe directory: {directory}")


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    _assert_safe_parent_chain(path)
    _durable_mkdir(path.parent)
    _assert_safe_parent_chain(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def _durable_unlink(path: Path) -> None:
    path.unlink(missing_ok=True)
    _durable_mkdir(path.parent)
    _fsync_directory(path.parent)


def _assert_regular(path: Path) -> None:
    _assert_safe_parent_chain(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ManagerConflict(f"refusing unsafe file: {path}")
    if info.st_mode & 0o022:
        raise ManagerConflict(f"refusing writable config: {path}")


@dataclass
class NaiveCredentialManager:
    caddyfile: Path
    state_file: Path
    backup_dir: Path
    public_host: str
    validate: Callable[[Path], dict]
    reload: Callable[[], None]
    probe: Callable[[], None]
    caddyfile_mode: int = 0o640
    traffic: TrafficCollector | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _recovery_failed: bool = field(default=False, init=False, repr=False)

    @lifecycle_synchronized
    def bootstrap(self) -> None:
        _assert_regular(self.caddyfile)
        if self._transaction_file.exists():
            self._recover_transaction()
        if self.state_file.exists():
            _assert_regular(self.state_file)
            state = self._read_state()
            text = self.caddyfile.read_text()
            if ACCOUNTING_BEGIN not in text and ACCOUNTING_END not in text:
                self._migrate_accounting(state, text)
            else:
                self._assert_consistent(state)
            self._archive_tombstones(state)
            return
        text = self.caddyfile.read_text()
        legacy_credentials = self._legacy_credentials(text)
        try:
            for username, _password in legacy_credentials:
                self._valid_username(username)
        except ValueError as exc:
            raise ManagerConflict("reserved accounting username in imported credentials") from exc
        users = [
            {
                "username": username,
                "password": password,
                "enabled": True,
                "quota_bytes": None,
                "disabled_reason": None,
                "created_at": _now(),
                "updated_at": _now(),
            }
            for username, password in legacy_credentials
        ]
        if not users:
            raise ManagerConflict("no NaiveProxy credentials found for initial import")
        state = {"version": 1, "host": self.public_host, "users": users, "tombstones": []}
        rendered = self._render_initial(text, state)
        _durable_mkdir(self.backup_dir)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        config_backup = self.backup_dir / f"{stamp}.Caddyfile"
        state_backup = self.backup_dir / f"{stamp}.users.json"
        _atomic_write(config_backup, self.caddyfile.read_bytes())
        _atomic_write(state_backup, b"")
        transaction = {
            "version": 1,
            "phase": "bootstrap_prepared",
            "config_backup": config_backup.name,
            "state_backup": state_backup.name,
            "state_existed": False,
        }
        self._write_transaction(transaction)
        self._write_validated_config(rendered)
        _atomic_write(self.state_file, self._encode_state(state))
        self._clear_transaction()
        self._prune_backups()

    def health(self) -> dict:
        try:
            traffic = self.traffic
            operation = traffic.operation() if traffic is not None else self._lock
            with operation, self._lock:
                if self._recovery_failed or self._transaction_file.exists():
                    raise ManagerRecoveryError("transaction recovery required")
                state = self._read_state()
                self._assert_consistent(state)
                self.probe()
                if traffic is not None:
                    # Health reports; it never rewrites the managed config.
                    # Quota enforcement runs on its own schedule.
                    traffic.collect()
                    if traffic.health().get("ready") is not True:
                        raise ManagerConflict("traffic accounting is unavailable")
                return {"ready": True, "host": self.public_host}
        except Exception:
            return {"ready": False, "host": self.public_host}

    @synchronized
    def list_users(self) -> list[dict]:
        state = self._read_state()
        return [
            {
                "username": row["username"],
                "enabled": bool(row["enabled"]),
                "quota_bytes": row["quota_bytes"],
                "disabled_reason": row["disabled_reason"],
            }
            for row in state["users"]
        ]

    def traffic_report(self) -> dict:
        if self.traffic is None:
            raise ManagerConflict("traffic accounting is unavailable")
        try:
            with self.traffic.operation(), self._lock:
                self.traffic.collect()
                return self.traffic.list_traffic()
        except (ManagerConflict, ManagerRecoveryError):
            raise
        except RuntimeError as exc:
            raise ManagerConflict("traffic accounting is degraded") from exc

    def enforce_quotas(self) -> list[str]:
        """Collect completed CONNECT records and disable newly exhausted users."""
        traffic = self.traffic
        if traffic is None:
            return []
        with traffic.operation(), self._lock:
            traffic.collect()
            report = traffic.list_traffic()
            return self._enforce_quotas_from_report_locked(report)

    def _used_bytes_locked(self, username: str) -> int:
        """Payload bytes recorded for a user, or 0 when accounting is unavailable."""
        traffic = self.traffic
        if traffic is None:
            return 0
        traffic.collect()
        report = traffic.list_traffic()
        return next(
            (
                row["total_bytes"]
                for row in report.get("users", [])
                if isinstance(row, dict)
                and row.get("username") == username
                and type(row.get("total_bytes")) is int
            ),
            0,
        )

    def _enforce_quotas_from_report_locked(self, report: dict) -> list[str]:
        usage = {
            row["username"]: row["total_bytes"]
            for row in report.get("users", [])
            if isinstance(row, dict)
            and isinstance(row.get("username"), str)
            and type(row.get("total_bytes")) is int
        }
        state = self._read_state()
        exhausted = []
        for row in state["users"]:
            quota = row["quota_bytes"]
            if row["enabled"] and quota is not None and usage.get(row["username"], 0) >= quota:
                row["enabled"] = False
                row["disabled_reason"] = "quota"
                row["updated_at"] = _now()
                exhausted.append(row["username"])
        if exhausted:
            self._apply(state)
        return exhausted

    def reset_traffic(self, username: str) -> dict:
        traffic = self.traffic
        if traffic is None:
            raise ManagerConflict("traffic accounting is unavailable")
        with traffic.operation(), self._lock:
            self._find(self._read_state(), username)
            try:
                if not traffic.drain():
                    raise ManagerConflict("traffic backlog remains pending")
                return traffic.reset(username)
            except ManagerConflict:
                raise
            except RuntimeError as exc:
                raise ManagerConflict("traffic accounting is degraded") from exc

    @synchronized
    def managed_usernames(self) -> set[str]:
        return {row["username"] for row in self._read_state()["users"]}

    @synchronized
    def reveal(self, username: str) -> dict:
        row = self._find(self._read_state(), username)
        user = quote(row["username"], safe="")
        password = quote(row["password"], safe="")
        proxy_url = f"https://{user}:{password}@{self.public_host}"
        return {
            "username": row["username"],
            "proxy_url": proxy_url,
            "config": {"listen": "socks://127.0.0.1:1080", "proxy": proxy_url},
        }

    @lifecycle_synchronized
    def create(self, username: str, quota_bytes: int | None = None) -> dict:
        self._valid_username(username)
        self._validate_quota(quota_bytes)
        state = self._read_state()
        if any(row["username"] == username for row in state["users"]):
            raise ManagerConflict("user already exists")
        if any(row["username"] == username for row in state["tombstones"]):
            raise ManagerConflict("username is permanently retired")
        timestamp = _now()
        state["users"].append({
            "username": username,
            "password": secrets.token_urlsafe(18),
            "enabled": True,
            "quota_bytes": quota_bytes,
            "disabled_reason": None,
            "created_at": timestamp,
            "updated_at": timestamp,
        })
        self._apply(state)
        return self.reveal(username)

    @lifecycle_synchronized
    def rotate(self, username: str) -> dict:
        state = self._read_state()
        row = self._find(state, username)
        row["password"] = secrets.token_urlsafe(18)
        row["updated_at"] = _now()
        self._apply(state)
        return self.reveal(username)

    @lifecycle_synchronized
    def set_enabled(self, username: str, enabled: bool) -> dict:
        state = self._read_state()
        row = self._find(state, username)
        if enabled and row["quota_bytes"] is not None:
            if self._used_bytes_locked(username) >= row["quota_bytes"]:
                raise ManagerConflict(
                    "quota exhausted; reset traffic or remove quota first", "quota_exhausted"
                )
        row["enabled"] = bool(enabled)
        row["disabled_reason"] = None if enabled else "manual"
        row["updated_at"] = _now()
        self._apply(state)
        return {
            "username": username,
            "enabled": bool(enabled),
            "disabled_reason": row["disabled_reason"],
        }

    @lifecycle_synchronized
    def set_quota(self, username: str, quota_bytes: int | None) -> dict:
        self._validate_quota(quota_bytes)
        state = self._read_state()
        row = self._find(state, username)
        used = self._used_bytes_locked(username)
        row["quota_bytes"] = quota_bytes
        if row["enabled"] and quota_bytes is not None and used >= quota_bytes:
            row["enabled"] = False
            row["disabled_reason"] = "quota"
        elif row["disabled_reason"] == "quota" and (quota_bytes is None or used < quota_bytes):
            # The quota no longer holds this user back, but access stays off
            # until the operator enables it: that remains a separate decision.
            row["disabled_reason"] = "manual"
        row["updated_at"] = _now()
        self._apply(state)
        return {
            "username": username,
            "quota_bytes": quota_bytes,
            "enabled": row["enabled"],
            "disabled_reason": row["disabled_reason"],
        }

    @lifecycle_synchronized
    def delete(self, username: str) -> None:
        traffic = self.traffic
        if traffic is None:
            raise ManagerConflict("traffic accounting is unavailable")
        state = self._read_state()
        self._find(state, username)
        try:
            if not traffic.drain():
                raise ManagerConflict("traffic backlog remains pending")
        except ManagerConflict:
            raise
        except RuntimeError as exc:
            raise ManagerConflict("traffic accounting is degraded") from exc
        state["users"] = [row for row in state["users"] if row["username"] != username]
        state["tombstones"].append({"username": username, "deleted_at": _now()})
        self._apply(state)
        traffic.archive_user(username)

    def _archive_tombstones(self, state: dict) -> None:
        if self.traffic is None:
            return
        for row in state["tombstones"]:
            self.traffic.archive_user(row["username"])

    def _apply(self, desired: dict) -> None:
        if self._recovery_failed or self._transaction_file.exists():
            raise ManagerRecoveryError("transaction recovery required before mutation")
        current = self._read_state()
        self._assert_consistent(current)
        config_before = self.caddyfile.read_bytes()
        state_before = self.state_file.read_bytes()
        rendered = self._render_managed(config_before.decode(), desired)
        _durable_mkdir(self.backup_dir)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        config_backup = self.backup_dir / f"{stamp}.Caddyfile"
        state_backup = self.backup_dir / f"{stamp}.users.json"
        _atomic_write(config_backup, config_before)
        _atomic_write(state_backup, state_before)
        transaction = {
            "version": 1,
            "phase": "prepared",
            "config_backup": config_backup.name,
            "state_backup": state_backup.name,
        }
        self._write_transaction(transaction)
        try:
            self._write_validated_config(rendered)
            _atomic_write(self.state_file, self._encode_state(desired))
            transaction["phase"] = "rollback_pending"
            self._write_transaction(transaction)
            self.reload()
            self.probe()
        except BaseException as operation_error:
            self._recovery_failed = True
            recovery_from = transaction["phase"]
            transaction["phase"] = "recovery_failed"
            transaction["recovery_from"] = recovery_from
            try:
                self._write_transaction(transaction)
                _atomic_write(self.caddyfile, config_before, self.caddyfile_mode)
                _atomic_write(self.state_file, state_before)
                self._validate_config(self.caddyfile)
                self.reload()
                self.probe()
            except Exception as rollback_error:
                raise ManagerRecoveryError("rollback failed; manager requires recovery") from rollback_error
            self._clear_transaction()
            self._recovery_failed = False
            self._prune_backups()
            raise operation_error
        self._clear_transaction()
        self._prune_backups()

    def _migrate_accounting(self, state: dict, text: str) -> None:
        actual = self._managed_credentials(text)
        expected = [(row["username"], row["password"]) for row in state["users"] if row["enabled"]]
        if actual != expected:
            raise ManagerConflict("managed Caddy credentials changed outside manager")
        self._validate_config(self.caddyfile)
        rendered = self._render_accounting_migration(text)
        config_before = self.caddyfile.read_bytes()
        state_before = self.state_file.read_bytes()
        _durable_mkdir(self.backup_dir)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        config_backup = self.backup_dir / f"{stamp}.Caddyfile"
        state_backup = self.backup_dir / f"{stamp}.users.json"
        _atomic_write(config_backup, config_before)
        _atomic_write(state_backup, state_before)
        transaction = {
            "version": 1,
            "phase": "prepared",
            "config_backup": config_backup.name,
            "state_backup": state_backup.name,
            "operation": "accounting_migration",
        }
        self._write_transaction(transaction)
        try:
            self._write_validated_config(rendered)
            _atomic_write(self.state_file, state_before)
            transaction["phase"] = "files_replaced"
            self._write_transaction(transaction)
            transaction["phase"] = "rollback_pending"
            self._write_transaction(transaction)
            self.reload()
            self.probe()
        except BaseException as operation_error:
            self._recovery_failed = True
            recovery_from = transaction["phase"]
            transaction["phase"] = "recovery_failed"
            transaction["recovery_from"] = recovery_from
            try:
                self._write_transaction(transaction)
                _atomic_write(self.caddyfile, config_before, self.caddyfile_mode)
                _atomic_write(self.state_file, state_before)
                self._validate_config(self.caddyfile)
                self.reload()
                self.probe()
            except Exception as rollback_error:
                raise ManagerRecoveryError("rollback failed; manager requires recovery") from rollback_error
            self._clear_transaction()
            self._recovery_failed = False
            self._prune_backups()
            raise operation_error
        self._clear_transaction()
        self._prune_backups()

    def _write_validated_config(self, rendered: str) -> None:
        _durable_mkdir(self.caddyfile.parent)
        fd, temporary = tempfile.mkstemp(prefix=".Caddyfile.naive.", dir=self.caddyfile.parent)
        path = Path(temporary)
        try:
            os.fchmod(fd, self.caddyfile_mode)
            with os.fdopen(fd, "w") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            self._validate_config(path)
            os.replace(path, self.caddyfile)
            os.chmod(self.caddyfile, self.caddyfile_mode)
            _fsync_directory(self.caddyfile.parent)
        finally:
            path.unlink(missing_ok=True)

    def _read_state(self) -> dict:
        _assert_regular(self.state_file)
        try:
            state = json.loads(self.state_file.read_text())
        except (OSError, ValueError) as exc:
            raise ManagerConflict("invalid manager state") from exc
        if state.get("version") != 1 or state.get("host") != self.public_host or not isinstance(state.get("users"), list):
            raise ManagerConflict("unsupported manager state")
        if set(state) - {"version", "host", "users", "tombstones"}:
            raise ManagerConflict("unsupported manager state")
        state.setdefault("tombstones", [])
        if not isinstance(state["tombstones"], list):
            raise ManagerConflict("invalid tombstone state")
        seen = set()
        for row in state["users"]:
            if not isinstance(row, dict):
                raise ManagerConflict("invalid user state")
            row.setdefault("quota_bytes", None)
            row.setdefault("disabled_reason", None)
            if set(row) - {
                "username", "password", "enabled", "quota_bytes", "disabled_reason",
                "created_at", "updated_at",
            }:
                raise ManagerConflict("invalid user state")
            try:
                self._valid_username(row.get("username", ""))
            except ValueError as exc:
                if row.get("username") == REDACTION_SENTINEL:
                    raise ManagerConflict(
                        "reserved accounting username in manager state"
                    ) from exc
                raise ManagerConflict("invalid user state") from exc
            if (
                row["username"] in seen
                or not isinstance(row.get("password"), str)
                or not row["password"]
                or type(row.get("enabled")) is not bool
                or not (
                    row["quota_bytes"] is None
                    or (
                        type(row["quota_bytes"]) is int
                        and 1 <= row["quota_bytes"] <= MAX_COUNTER
                    )
                )
                or row["disabled_reason"] not in DISABLED_REASONS
                or (row["enabled"] and row["disabled_reason"] is not None)
                or (
                    row["disabled_reason"] == "quota"
                    and row["quota_bytes"] is None
                )
            ):
                raise ManagerConflict("invalid user state")
            seen.add(row["username"])
        retired = set()
        for row in state["tombstones"]:
            if (
                not isinstance(row, dict)
                or set(row) != {"username", "deleted_at"}
                or not isinstance(row.get("deleted_at"), str)
            ):
                raise ManagerConflict("invalid tombstone state")
            try:
                self._valid_username(row.get("username", ""))
            except ValueError as exc:
                if row.get("username") == REDACTION_SENTINEL:
                    raise ManagerConflict(
                        "reserved accounting username in manager state"
                    ) from exc
                raise ManagerConflict("invalid tombstone state") from exc
            if row["username"] in seen or row["username"] in retired:
                raise ManagerConflict("invalid tombstone state")
            retired.add(row["username"])
        return copy.deepcopy(state)

    @property
    def _transaction_file(self) -> Path:
        return self.state_file.parent / "transaction.json"

    def _read_transaction(self) -> dict:
        _assert_regular(self._transaction_file)
        try:
            transaction = json.loads(self._transaction_file.read_text())
        except (OSError, ValueError) as exc:
            raise ManagerRecoveryError("invalid transaction journal") from exc
        phases = {"bootstrap_prepared", "prepared", "files_replaced", "rollback_pending", "recovery_failed"}
        if (
            not isinstance(transaction, dict)
            or type(transaction.get("version")) is not int
            or transaction["version"] != 1
            or transaction.get("phase") not in phases
        ):
            raise ManagerRecoveryError("invalid transaction journal")
        base_keys = {"version", "phase", "config_backup", "state_backup"}
        operation = transaction.get("operation")
        if operation is not None:
            if operation != "accounting_migration":
                raise ManagerRecoveryError("invalid transaction journal")
            base_keys.add("operation")
        phase = transaction["phase"]
        if phase == "bootstrap_prepared":
            allowed_keys = base_keys | {"state_existed"}
            valid_shape = transaction.get("state_existed") is False
        elif phase == "recovery_failed":
            recovery_from = transaction.get("recovery_from")
            valid_origins = {"bootstrap_prepared", "prepared", "files_replaced", "rollback_pending"}
            allowed_keys = base_keys | {"recovery_from"}
            valid_shape = recovery_from in valid_origins
            if recovery_from == "bootstrap_prepared":
                allowed_keys.add("state_existed")
                valid_shape = valid_shape and transaction.get("state_existed") is False
        else:
            allowed_keys = base_keys
            valid_shape = True
        if not valid_shape or set(transaction) != allowed_keys:
            raise ManagerRecoveryError("invalid transaction journal")
        config_name = transaction.get("config_backup")
        state_name = transaction.get("state_backup")
        if (
            not isinstance(config_name, str)
            or not isinstance(state_name, str)
            or Path(config_name).name != config_name
            or Path(state_name).name != state_name
            or not config_name.endswith(".Caddyfile")
            or not state_name.endswith(".users.json")
            or config_name.removesuffix(".Caddyfile") != state_name.removesuffix(".users.json")
            or not config_name.removesuffix(".Caddyfile")
        ):
            raise ManagerRecoveryError("invalid transaction journal")
        return transaction

    def _write_transaction(self, transaction: dict) -> None:
        _atomic_write(self._transaction_file, (json.dumps(transaction, separators=(",", ":")) + "\n").encode())

    def _clear_transaction(self) -> None:
        _durable_unlink(self._transaction_file)

    def _recover_transaction(self) -> None:
        transaction = self._read_transaction()
        original_phase = transaction.get("recovery_from", transaction["phase"])
        transaction["phase"] = "recovery_failed"
        transaction["recovery_from"] = original_phase
        self._write_transaction(transaction)

        def restore_backups() -> None:
            config_backup = self.backup_dir / transaction["config_backup"]
            state_backup = self.backup_dir / transaction["state_backup"]
            _assert_regular(config_backup)
            _assert_regular(state_backup)
            _atomic_write(self.caddyfile, config_backup.read_bytes(), self.caddyfile_mode)
            if transaction.get("state_existed", True):
                _atomic_write(self.state_file, state_backup.read_bytes())
            else:
                _durable_unlink(self.state_file)

        def activate_current() -> None:
            state = self._read_state()
            self._assert_consistent(state)
            self.reload()
            self.probe()

        def activate_pre_accounting() -> None:
            state = self._read_state()
            text = self.caddyfile.read_text()
            actual = self._managed_credentials(text)
            expected = [
                (row["username"], row["password"])
                for row in state["users"] if row["enabled"]
            ]
            if actual != expected:
                raise ManagerConflict("managed Caddy credentials changed outside manager")
            self._validate_config(self.caddyfile)
            self.reload()
            self.probe()

        try:
            if original_phase == "bootstrap_prepared":
                restore_backups()
                self._clear_transaction()
                self._recovery_failed = False
                return
            if transaction.get("operation") == "accounting_migration":
                restore_backups()
                activate_pre_accounting()
            elif original_phase in {"prepared", "rollback_pending", "recovery_failed"}:
                restore_backups()
                activate_current()
            else:
                try:
                    activate_current()
                except Exception:
                    restore_backups()
                    activate_current()
            self._clear_transaction()
            self._recovery_failed = False
        except Exception as exc:
            self._recovery_failed = True
            raise ManagerRecoveryError("transaction recovery failed") from exc

    def _assert_consistent(self, state: dict) -> None:
        text = self.caddyfile.read_text()
        self._assert_accounting_config(text)
        actual = self._managed_credentials(text)
        expected = [(row["username"], row["password"]) for row in state["users"] if row["enabled"]]
        if actual != expected:
            raise ManagerConflict("managed Caddy credentials changed outside manager")
        self._validate_config(self.caddyfile)

    def _validate_config(self, path: Path) -> None:
        expected_count = len(self._managed_credentials(path.read_text()))
        config = self.validate(path)
        self._assert_adapted_semantics(config, expected_count)

    @staticmethod
    def _assert_adapted_semantics(config: dict, expected_credentials: int) -> None:
        if not isinstance(config, dict):
            raise ManagerConflict("invalid adapted Caddy configuration")
        handlers = []

        def walk(value) -> None:
            if isinstance(value, dict):
                if isinstance(value.get("handler"), str):
                    handlers.append(value)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(config)
        forward = [node for node in handlers if node["handler"] == "forward_proxy"]
        authentication = [node for node in handlers if node["handler"] == "authentication"]
        if len(forward) != 1 or authentication:
            raise ManagerConflict("unexpected proxy or authentication handler")
        credentials = forward[0].get("auth_credentials")
        if (
            not isinstance(credentials, list)
            or len(credentials) != expected_credentials
            or any(not isinstance(value, str) or not value for value in credentials)
        ):
            raise ManagerConflict("adapted proxy credentials do not match managed state")

    @staticmethod
    def _find(state: dict, username: str) -> dict:
        for row in state["users"]:
            if row["username"] == username:
                return row
        raise ManagerNotFound("user not found")

    @staticmethod
    def _valid_username(username: str) -> None:
        if not isinstance(username, str) or USERNAME.fullmatch(username) is None:
            raise ValueError("invalid username")
        if username == REDACTION_SENTINEL:
            raise ValueError("reserved username")

    @staticmethod
    def _validate_quota(quota_bytes: int | None) -> None:
        if quota_bytes is not None and (
            type(quota_bytes) is not int or not 1 <= quota_bytes <= MAX_COUNTER
        ):
            raise ValueError("invalid quota bytes")

    @staticmethod
    def _encode_state(state: dict) -> bytes:
        return (json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode()

    @staticmethod
    def _forward_bounds(lines: list[str]) -> tuple[int, int]:
        directives = [index for index, line in enumerate(lines) if re.match(r"^\s*forward_proxy(?:\s|$)", line)]
        if len(directives) != 1:
            raise ManagerConflict("exactly one forward_proxy block is required")
        start = directives[0]
        if re.fullmatch(r"\s*forward_proxy\s*\{\s*(?:#.*)?", lines[start]) is None:
            raise ManagerConflict("forward_proxy must use managed block form")
        depth = 0
        for index in range(start, len(lines)):
            depth += lines[index].count("{") - lines[index].count("}")
            if index > start and depth == 0:
                return start, index
        raise ManagerConflict("unterminated forward_proxy block")

    @classmethod
    def _legacy_credentials(cls, text: str) -> list[tuple[str, str]]:
        lines = text.splitlines()
        start, end = cls._forward_bounds(lines)
        credentials = []
        for line in lines[start + 1:end]:
            match = re.match(r"^\s*basic_auth\s+(\S+)\s+(\S+)\s*$", line)
            if match:
                credentials.append((match.group(1), match.group(2)))
        return credentials

    @classmethod
    def _managed_bounds(cls, lines: list[str]) -> tuple[int, int]:
        begin_indexes = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
        end_indexes = [i for i, line in enumerate(lines) if line.strip() == END]
        if len(begin_indexes) != 1 or len(end_indexes) != 1:
            raise ManagerConflict("managed credential block must have exactly one marker pair")
        start, end = begin_indexes[0], end_indexes[0]
        forward_start, forward_end = cls._forward_bounds(lines)
        if not forward_start < start < end < forward_end:
            raise ManagerConflict("managed credential block is outside forward_proxy")
        for index in range(len(lines)):
            if re.match(r"^\s*basic_auth\s+", lines[index]) and not start < index < end:
                raise ManagerConflict("basic_auth directive outside managed credential block")
        return start, end

    @classmethod
    def _managed_credentials(cls, text: str) -> list[tuple[str, str]]:
        lines = text.splitlines()
        start, end = cls._managed_bounds(lines)
        credentials = []
        for line in lines[start + 1:end]:
            match = re.match(r"^\s*basic_auth\s+(\S+)\s+(\S+)\s*$", line)
            if not match:
                raise ManagerConflict("invalid managed credential directive")
            credentials.append((match.group(1), match.group(2)))
        return credentials

    @classmethod
    def _render_initial(cls, text: str, state: dict) -> str:
        lines = text.splitlines()
        if any(line.strip() in {BEGIN, END, ACCOUNTING_BEGIN, ACCOUNTING_END} for line in lines):
            raise ManagerConflict("managed credential markers already present")
        start, end = cls._forward_bounds(lines)
        auth_indexes = [i for i in range(start + 1, end) if re.match(r"^\s*basic_auth\s+", lines[i])]
        if not auth_indexes:
            raise ManagerConflict("basic_auth directives not found")
        indent = re.match(r"^(\s*)", lines[auth_indexes[0]]).group(1)
        block = cls._credential_lines(state, indent)
        first = auth_indexes[0]
        lines = [line for i, line in enumerate(lines) if i not in set(auth_indexes)]
        lines[first:first] = block
        start, end = cls._forward_bounds(lines)
        host_indexes = [i for i in range(start + 1, end) if re.match(r"^\s*hosts(?:\s|$)", lines[i])]
        cover_host = f"hosts {state['host']}"
        if not host_indexes:
            lines[end:end] = [f"{indent}{cover_host}"]
        elif len(host_indexes) != 1 or lines[host_indexes[0]].strip() != cover_host:
            raise ManagerConflict("forward_proxy hosts must match the managed public host")
        route_indexes = [i for i, line in enumerate(lines) if re.match(r"^\s*route\s*\{", line)]
        if len(route_indexes) != 1:
            raise ManagerConflict("exactly one route block is required")
        route_index = route_indexes[0]
        site_indent = re.match(r"^(\s*)", lines[route_index]).group(1)
        lines[route_index:route_index] = cls._accounting_lines(site_indent)
        return "\n".join(lines) + "\n"

    @classmethod
    def _render_managed(cls, text: str, state: dict) -> str:
        lines = text.splitlines()
        start, end = cls._managed_bounds(lines)
        indent = re.match(r"^(\s*)", lines[start]).group(1)
        lines[start:end + 1] = cls._credential_lines(state, indent)
        return "\n".join(lines) + "\n"

    @classmethod
    def _render_accounting_migration(cls, text: str) -> str:
        lines = text.splitlines()
        if any(line.strip() in {ACCOUNTING_BEGIN, ACCOUNTING_END} for line in lines):
            raise ManagerConflict("partial accounting markers are not migratable")
        cls._managed_bounds(lines)
        route_indexes = [i for i, line in enumerate(lines) if re.match(r"^\s*route\s*\{", line)]
        if len(route_indexes) != 1:
            raise ManagerConflict("exactly one route block is required")
        route_index = route_indexes[0]
        indent = re.match(r"^(\s*)", lines[route_index]).group(1)
        lines[route_index:route_index] = cls._accounting_lines(indent)
        return "\n".join(lines) + "\n"

    @staticmethod
    def _credential_lines(state: dict, indent: str) -> list[str]:
        rows = [f"{indent}basic_auth {row['username']} {row['password']}" for row in state["users"] if row["enabled"]]
        return [f"{indent}{BEGIN}", *rows, f"{indent}{END}"]

    @staticmethod
    def _accounting_lines(indent: str) -> list[str]:
        inner = indent + "    "
        deep = inner + "    "
        return [
            f"{indent}{ACCOUNTING_BEGIN}",
            f"{indent}log naive_accounting {{",
            f"{inner}output file /var/log/naive-proxy/access.json {{",
            f"{deep}mode 0640",
            f"{deep}roll_size {ACCOUNTING_ROLL_SIZE_BYTES // (1024 * 1024)}MiB",
            f"{deep}roll_keep {ACCOUNTING_ROLL_KEEP}",
            f"{deep}roll_keep_for 168h",
            f"{deep}roll_uncompressed",
            f"{inner}}}",
            f"{inner}format filter {{",
            f"{deep}wrap json",
            f"{deep}fields {{",
            f"{deep}    request>headers>Proxy-Authorization delete",
            f"{deep}    user_id regexp ^(invalidbase64|invalidformat|invalid):.*$ invalid",
            f"{deep}}}",
            f"{inner}}}",
            f"{indent}}}",
            f"{indent}{ACCOUNTING_END}",
        ]

    @classmethod
    def _assert_accounting_config(cls, text: str) -> None:
        lines = text.splitlines()
        begins = [i for i, line in enumerate(lines) if line.strip() == ACCOUNTING_BEGIN]
        ends = [i for i, line in enumerate(lines) if line.strip() == ACCOUNTING_END]
        if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
            raise ManagerConflict("managed accounting block must have exactly one marker pair")
        indent = re.match(r"^(\s*)", lines[begins[0]]).group(1)
        if lines[begins[0]:ends[0] + 1] != cls._accounting_lines(indent):
            raise ManagerConflict("managed accounting block changed outside manager")

    def _prune_backups(self) -> None:
        backups = sorted(self.backup_dir.glob("*.Caddyfile"), reverse=True)
        for old in backups[20:]:
            old.unlink(missing_ok=True)
            old.with_name(old.name.removesuffix(".Caddyfile") + ".users.json").unlink(missing_ok=True)
