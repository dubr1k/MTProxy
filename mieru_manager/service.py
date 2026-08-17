"""Transactional, fail-closed manager for the separate GPL mita v3.35 daemon."""

from __future__ import annotations

import copy
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import selectors
import secrets
import signal
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode


SUPPORTED_VERSION = re.compile(r"(?:mita\s+)?(3\.35\.\d+)\Z")
LOG_LEVELS = {"DEFAULT", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"}
TRANSPORTS = {"TCP", "UDP"}
DUAL_STACK = {"USE_FIRST_IP", "PREFER_IPv4", "PREFER_IPv6", "ONLY_IPv4", "ONLY_IPv6"}
TOP_FIELDS = {
    "portBindings",
    "users",
    "advancedSettings",
    "loggingLevel",
    "mtu",
    "egress",
    "dns",
    "trafficPattern",
}
USER_FIELDS = {
    "name",
    "password",
    "hashedPassword",
    "quotas",
    "allowPrivateIP",
    "allowLoopbackIP",
}
PORT_FIELDS = {"port", "protocol", "portRange"}
QUOTA_FIELDS = {"days", "megabytes"}
MAX_QUOTA_DAYS = 2**31 - 1
MAX_QUOTA_MIB = 2**31 - 1
MAX_GO_DURATION_NS = 2**63 - 1
TRANSACTION_MODES = {
    "user.create": "dynamic",
    "user.rotate": "restart",
    "user.enable": "restart",
    "user.disable": "restart",
    "user.delete": "restart",
    "user.quotas": "reload",
}
_DURATION_UNITS_NS = {
    "ns": Decimal(1),
    "us": Decimal(1_000),
    "µs": Decimal(1_000),
    "μs": Decimal(1_000),
    "ms": Decimal(1_000_000),
    "s": Decimal(1_000_000_000),
    "m": Decimal(60_000_000_000),
    "h": Decimal(3_600_000_000_000),
}


class ValidationError(ValueError):
    pass


class ConfigConflict(RuntimeError):
    pass


class MitaError(RuntimeError):
    pass


def _object(value: Any, fields: set[str], name: str) -> dict:
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must be an object")
    unknown = set(value) - fields
    if unknown:
        raise ValidationError(f"{name} contains unknown fields")
    return value


def _positive_int(value: Any, low: int, high: int, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not low <= value <= high
    ):
        raise ValidationError(f"invalid {name}")
    return value


def _go_duration_ns(value: Any) -> int:
    if not isinstance(value, str) or not value:
        raise ValidationError("invalid metrics interval")
    sign = 1
    body = value
    if body[0] in "+-":
        sign = -1 if body[0] == "-" else 1
        body = body[1:]
    token = re.compile(
        r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:ns|us|µs|μs|ms|s|m|h)"
    )
    position = 0
    total = Decimal(0)
    try:
        for match in token.finditer(body):
            if match.start() != position:
                raise ValidationError("invalid metrics interval")
            part = match.group(0)
            unit = next(unit for unit in _DURATION_UNITS_NS if part.endswith(unit))
            total += Decimal(part[: -len(unit)]) * _DURATION_UNITS_NS[unit]
            position = match.end()
    except (InvalidOperation, StopIteration) as exc:
        raise ValidationError("invalid metrics interval") from exc
    if position != len(body) or position == 0:
        raise ValidationError("invalid metrics interval")
    nanoseconds = sign * int(total)
    if not -(2**63) <= nanoseconds <= MAX_GO_DURATION_NS:
        raise ValidationError("invalid metrics interval")
    return nanoseconds


def _validate_traffic(value: Any) -> None:
    traffic = _object(
        value,
        {"seed", "unlockAll", "tcpFragment", "nonce", "padding", "lowEntropy"},
        "trafficPattern",
    )
    if "seed" in traffic and (
        isinstance(traffic["seed"], bool)
        or not isinstance(traffic["seed"], int)
        or not -(2**31) <= traffic["seed"] <= 2**31 - 1
    ):
        raise ValidationError("invalid traffic pattern seed")
    if "unlockAll" in traffic and not isinstance(traffic["unlockAll"], bool):
        raise ValidationError("invalid traffic pattern unlockAll")
    if "tcpFragment" in traffic:
        node = _object(traffic["tcpFragment"], {"enable", "maxSleepMs"}, "tcpFragment")
        if "enable" in node and not isinstance(node["enable"], bool):
            raise ValidationError("invalid traffic pattern fragment")
        if "maxSleepMs" in node:
            _positive_int(node["maxSleepMs"], 0, 100, "traffic fragment delay")
    if "nonce" in traffic:
        node = _object(
            traffic["nonce"],
            {"type", "applyToAllUDPPacket", "minLen", "maxLen", "customHexStrings"},
            "nonce",
        )
        if node.get("type", "NONCE_TYPE_RANDOM") not in {
            "NONCE_TYPE_RANDOM",
            "NONCE_TYPE_PRINTABLE",
            "NONCE_TYPE_PRINTABLE_SUBSET",
            "NONCE_TYPE_FIXED",
        }:
            raise ValidationError("invalid traffic nonce type")
        if "applyToAllUDPPacket" in node and not isinstance(
            node["applyToAllUDPPacket"], bool
        ):
            raise ValidationError("invalid traffic nonce UDP setting")
        for key in ("minLen", "maxLen"):
            if key in node:
                _positive_int(node[key], 0, 12, f"nonce {key}")
        if node.get("minLen", 0) > node.get("maxLen", 12):
            raise ValidationError("invalid traffic nonce length range")
        custom = node.get("customHexStrings", [])
        if (
            not isinstance(custom, list)
            or len(custom) > 64
            or any(
                not isinstance(item, str)
                or len(item) > 24
                or len(item) % 2
                or re.fullmatch(r"[0-9a-fA-F]*", item) is None
                for item in custom
            )
        ):
            raise ValidationError("invalid traffic nonce custom strings")
    if "padding" in traffic:
        node = _object(
            traffic["padding"], {"maxMiddlePaddingLen", "maxEndPaddingLen"}, "padding"
        )
        for key, item in node.items():
            _positive_int(item, 0, 255, f"padding {key}")
    if "lowEntropy" in traffic:
        node = _object(traffic["lowEntropy"], {"mode", "maskRotation"}, "lowEntropy")
        if node.get("mode", "LOW_ENTROPY_MODE_OFF") not in {
            "LOW_ENTROPY_MODE_OFF",
            "LOW_ENTROPY_MODE_32",
            "LOW_ENTROPY_MODE_40",
            "LOW_ENTROPY_MODE_48",
            "LOW_ENTROPY_MODE_56",
        }:
            raise ValidationError("invalid low entropy mode")
        rotations = {"LOW_ENTROPY_MASK_NO_ROTATION"}
        rotations.update(
            f"LOW_ENTROPY_MASK_ROTATE_{direction}_{amount}"
            for direction in ("RIGHT", "LEFT")
            for amount in range(1, 16)
        )
        if node.get("maskRotation", "LOW_ENTROPY_MASK_NO_ROTATION") not in rotations:
            raise ValidationError("invalid mask rotation")


def validate_config(config: Any, *, elevated: bool = False) -> dict:
    config = _object(config, TOP_FIELDS, "config")
    bindings = config.get("portBindings")
    if not isinstance(bindings, list) or not bindings:
        raise ValidationError("at least one port binding is required")
    occupied: dict[str, set[int]] = {"TCP": set(), "UDP": set()}
    for binding in bindings:
        binding = _object(binding, PORT_FIELDS, "port binding")
        protocol = binding.get("protocol")
        if protocol not in TRANSPORTS:
            raise ValidationError("invalid transport protocol")
        if ("port" in binding) == ("portRange" in binding):
            raise ValidationError("binding requires exactly one port or range")
        if "port" in binding:
            ports = [_positive_int(binding["port"], 1, 65535, "port")]
        else:
            match = re.fullmatch(
                r"([0-9]{1,5})-([0-9]{1,5})", str(binding["portRange"])
            )
            if not match:
                raise ValidationError("invalid port range")
            start, end = map(int, match.groups())
            if not 1 <= start <= end <= 65535:
                raise ValidationError("invalid port range")
            ports = range(start, end + 1)
        if occupied[protocol].intersection(ports):
            raise ValidationError("port bindings overlap")
        occupied[protocol].update(ports)

    users = config.get("users", [])
    if not isinstance(users, list):
        raise ValidationError("users must be a list")
    names: set[str] = set()
    for user in users:
        user = _object(user, USER_FIELDS, "user")
        name = user.get("name")
        if not isinstance(name, str) or not name or len(name.encode()) > 64:
            raise ValidationError("user name must be nonempty and at most 64 bytes")
        if name in names:
            raise ValidationError("duplicate user name")
        names.add(name)
        raw, hashed = user.get("password"), user.get("hashedPassword")
        if bool(raw) == bool(hashed):
            raise ValidationError("user requires exactly one credential")
        if raw is not None and (not isinstance(raw, str) or len(raw.encode()) > 64):
            raise ValidationError("password must be at most 64 bytes")
        if hashed is not None and (
            not isinstance(hashed, str) or re.fullmatch(r"[0-9a-f]{64}", hashed) is None
        ):
            raise ValidationError("invalid hashed password")
        quotas = user.get("quotas", [])
        if not isinstance(quotas, list):
            raise ValidationError("invalid quota list")
        for quota in quotas:
            quota = _object(quota, QUOTA_FIELDS, "quota")
            if set(quota) != QUOTA_FIELDS:
                raise ValidationError("quota requires days and megabytes")
            _positive_int(quota["days"], 1, MAX_QUOTA_DAYS, "quota days")
            _positive_int(quota["megabytes"], 1, MAX_QUOTA_MIB, "quota MiB")
        for flag in ("allowPrivateIP", "allowLoopbackIP"):
            if flag in user and not isinstance(user[flag], bool):
                raise ValidationError(f"invalid {flag}")
            if user.get(flag) and not elevated:
                raise ValidationError(
                    "private/loopback SSRF flags require elevated approval"
                )

    mtu = config.get("mtu", 1400)
    if isinstance(mtu, bool) or not isinstance(mtu, int) or not 1280 <= mtu <= 1500:
        raise ValidationError("MTU must be 1280 through 1500")
    if config.get("loggingLevel", "DEFAULT") not in LOG_LEVELS:
        raise ValidationError("invalid logging level")
    if "advancedSettings" in config:
        node = _object(
            config["advancedSettings"],
            {"metricsLoggingInterval", "userHintIsMandatory"},
            "advanced settings",
        )
        if "metricsLoggingInterval" in node:
            if _go_duration_ns(node["metricsLoggingInterval"]) < 1_000_000_000:
                raise ValidationError("invalid metrics interval")
        if "userHintIsMandatory" in node and not isinstance(
            node["userHintIsMandatory"], bool
        ):
            raise ValidationError("invalid user hint setting")
    if "dns" in config:
        dns = _object(config["dns"], {"dualStack", "hosts"}, "DNS")
        if dns.get("dualStack", "USE_FIRST_IP") not in DUAL_STACK:
            raise ValidationError("invalid DNS dual-stack mode")
        hosts = dns.get("hosts", {})
        if not isinstance(hosts, dict):
            raise ValidationError("invalid DNS hosts")
        for host, address in hosts.items():
            if (
                not isinstance(host, str)
                or not host
                or host.strip(".") != host
                or len(host) > 253
                or re.fullmatch(r"[A-Za-z0-9.-]+", host) is None
            ):
                raise ValidationError("invalid DNS host")
            try:
                ipaddress.ip_address(address)
            except (ValueError, TypeError) as exc:
                raise ValidationError("invalid DNS address") from exc
    if "egress" in config:
        egress = _object(config["egress"], {"proxies", "rules"}, "egress")
        proxies = egress.get("proxies", [])
        rules = egress.get("rules", [])
        if not isinstance(proxies, list) or not isinstance(rules, list):
            raise ValidationError("invalid egress lists")
        proxy_names = set()
        for proxy in proxies:
            proxy = _object(
                proxy,
                {"name", "protocol", "host", "port", "socks5Authentication"},
                "egress proxy",
            )
            if (
                not isinstance(proxy.get("name"), str)
                or not proxy["name"]
                or proxy["name"] in proxy_names
            ):
                raise ValidationError("invalid egress proxy name")
            proxy_names.add(proxy["name"])
            if (
                proxy.get("protocol") != "SOCKS5_PROXY_PROTOCOL"
                or not isinstance(proxy.get("host"), str)
                or not proxy["host"]
            ):
                raise ValidationError("invalid egress proxy")
            _positive_int(proxy.get("port"), 1, 65535, "egress port")
            if "socks5Authentication" in proxy:
                auth = _object(
                    proxy["socks5Authentication"],
                    {"user", "password"},
                    "egress authentication",
                )
                if set(auth) != {"user", "password"} or not all(
                    isinstance(item, str) and item for item in auth.values()
                ):
                    raise ValidationError("invalid egress authentication")
        for rule in rules:
            rule = _object(
                rule, {"ipRanges", "domainNames", "action", "proxyNames"}, "egress rule"
            )
            action = rule.get("action", "PROXY")
            if action not in {"PROXY", "DIRECT", "REJECT"}:
                raise ValidationError("invalid egress action")
            names = rule.get("proxyNames", [])
            if not isinstance(names, list) or any(
                not isinstance(name, str) for name in names
            ):
                raise ValidationError("invalid egress proxy name list")
            if action == "PROXY" and not names:
                raise ValidationError("egress rule proxy name list is empty")
            if action != "PROXY" and names:
                raise ValidationError(
                    "egress rule proxy names must be empty for non-PROXY action"
                )
            if any(name not in proxy_names for name in names):
                raise ValidationError("egress rule names unknown proxy")
            ip_ranges = rule.get("ipRanges", [])
            domains = rule.get("domainNames", [])
            if not isinstance(ip_ranges, list) or not isinstance(domains, list):
                raise ValidationError("invalid egress match list")
            for value in ip_ranges:
                if value != "*":
                    try:
                        ipaddress.ip_network(value, strict=False)
                    except (ValueError, TypeError) as exc:
                        raise ValidationError("invalid egress CIDR") from exc
            for value in domains:
                if not isinstance(value, str) or not value or value.strip(".") != value:
                    raise ValidationError("invalid egress domain")
    if "trafficPattern" in config:
        _validate_traffic(config["trafficPattern"])
    return config


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _transaction_mode(operation: str, before: dict, desired: dict) -> str:
    mode = TRANSACTION_MODES.get(operation)
    if mode is None:
        raise ValidationError("invalid transaction metadata")
    if mode != "dynamic":
        return mode
    old_names = {row.get("name") for row in before.get("users", [])}
    added = [row for row in desired.get("users", []) if row.get("name") not in old_names]
    return (
        "restart"
        if any(row.get("allowPrivateIP") is True or row.get("allowLoopbackIP") is True for row in added)
        else "reload"
    )


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            data = value if isinstance(value, bytes) else _canonical(value) + b"\n"
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        _fsync_dir(path.parent)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        Path(name).unlink(missing_ok=True)


def _read_secure(path: Path, *, max_size: int) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
            raise OSError("unsafe file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            after = os.fstat(fd)
            if (
                (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or not stat.S_ISREG(after.st_mode)
                or stat.S_IMODE(after.st_mode) != 0o600
                or after.st_size > max_size
            ):
                raise OSError("unsafe file")
            chunks = []
            remaining = max_size + 1
            while remaining:
                chunk = os.read(fd, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > max_size:
                raise OSError("unsafe file")
            return data
        finally:
            os.close(fd)
    except OSError as exc:
        raise ConfigConflict("unsafe transaction recovery file") from exc


class MitaCLI:
    """Narrow argv-only CLI boundary; secret snapshots and output use anonymous FDs."""

    def __init__(
        self,
        executable: Path | str = "/usr/bin/mita",
        *,
        env: dict[str, str] | None = None,
        timeout: float = 10,
        max_output: int = 1_048_576,
        expected_sha256: str | None = None,
    ):
        self.executable = str(executable)
        self.env = dict(env or {})
        self.timeout = timeout
        self.max_output = max_output
        self.expected_sha256 = expected_sha256

    def verify_executable(self) -> None:
        if self.expected_sha256 is None:
            return
        if re.fullmatch(r"[0-9a-f]{64}", self.expected_sha256) is None:
            raise MitaError("invalid pinned mita executable digest")
        try:
            info = os.stat(self.executable, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise OSError("unsafe executable")
            digest = hashlib.sha256()
            with open(self.executable, "rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
        except OSError as exc:
            raise MitaError("pinned mita executable is unavailable") from exc
        if not secrets.compare_digest(digest.hexdigest(), self.expected_sha256):
            raise MitaError("pinned mita executable digest mismatch")

    def _run(
        self, args: list[str], *, input_value: Any | None = None, output: bool = False
    ) -> bytes:
        self.verify_executable()
        input_stream = None
        try:
            command = [self.executable, *args]
            pass_fds = []
            if input_value is not None:
                input_stream = tempfile.TemporaryFile()
                input_fd = input_stream.fileno()
                payload = _canonical(input_value)
                if len(payload) > self.max_output:
                    raise MitaError("configuration is too large")
                input_stream.write(payload)
                input_stream.flush()
                input_stream.seek(0)
                command.append(f"/proc/self/fd/{input_fd}")
                pass_fds.append(input_fd)
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=tuple(pass_fds),
                    env={**os.environ, **self.env},
                    start_new_session=True,
                )
            except OSError as exc:
                raise MitaError("mita operation unavailable") from exc
            selector = selectors.DefaultSelector()
            stdout = process.stdout
            stderr = process.stderr
            assert stdout is not None and stderr is not None
            for stream in (stdout, stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            stdout_chunks: list[bytes] = []
            total = 0
            deadline = time.monotonic() + self.timeout
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise MitaError("mita operation unavailable")
                    events = selector.select(remaining)
                    if not events:
                        raise MitaError("mita operation unavailable")
                    for key, _ in events:
                        chunk = os.read(key.fd, min(65_536, self.max_output + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        total += len(chunk)
                        if total > self.max_output:
                            raise MitaError("mita response is too large")
                        if key.fileobj is stdout:
                            stdout_chunks.append(chunk)
                returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError as exc:
                    raise MitaError("mita operation unavailable") from exc
            except BaseException as exc:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for stream in (stdout, stderr):
                    try:
                        selector.unregister(stream)
                    except (KeyError, ValueError):
                        pass
                    stream.close()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired as wait_error:
                    raise MitaError("mita operation unavailable") from wait_error
                if isinstance(exc, subprocess.TimeoutExpired):
                    raise MitaError("mita operation unavailable") from exc
                raise
            finally:
                selector.close()
            if returncode != 0:
                raise MitaError("mita operation failed")
            if not output:
                return b""
            return b"".join(stdout_chunks)
        finally:
            if input_stream is not None:
                input_stream.close()

    def _text(self, args: list[str]) -> str:
        try:
            return self._run(args, output=True).decode().strip()
        except UnicodeDecodeError as exc:
            raise MitaError("mita returned invalid output") from exc

    def version(self) -> str:
        return self._text(["version"]).removeprefix("mita ")

    def observe(self) -> dict:
        try:
            value = json.loads(self._text(["describe", "config"]))
        except (ValueError, TypeError) as exc:
            raise MitaError("mita returned invalid configuration") from exc
        if not isinstance(value, dict):
            raise MitaError("mita returned invalid configuration")
        return value

    def apply(self, config: dict) -> None:
        self._run(["apply", "config"], input_value=config)

    def reload(self) -> None:
        self._run(["reload"])

    def stop(self) -> None:
        self._run(["stop"])

    def start(self) -> None:
        self._run(["start"])

    def status(self) -> str:
        text = self._text(["status"])
        match = re.fullmatch(
            r'mita server status is "(RUNNING|IDLE|STARTING|STOPPING|STOPPED|UNKNOWN)"',
            text,
        )
        if match is None:
            raise MitaError("mita returned invalid status")
        return match.group(1)

    def metrics(self) -> dict:
        raise MitaError("typed per-user metrics are unavailable in the mita v3.35 CLI")

    def probe(self) -> None:
        if self.status() != "RUNNING":
            raise MitaError("mita is not running")


class MieruManager:
    def __init__(
        self,
        *,
        mita: Any,
        state_dir: Path,
        public_host: str,
        protocol_probe: Callable[[], None] | None = None,
        status_timeout: float = 10,
        status_poll_interval: float = 0.05,
    ):
        self.mita, self.state_dir, self.public_host = mita, Path(state_dir), public_host
        self.protocol_probe = protocol_probe or mita.probe
        self.status_timeout = status_timeout
        self.status_poll_interval = status_poll_interval
        self._lock = threading.RLock()
        self.state_file = self.state_dir / "state.json"
        self.journal_file = self.state_dir / "journal.json"
        self.journal_key_file = self.state_dir / "journal.key"
        self.backup_dir = self.state_dir / "backups"
        self.lock_file = self.state_dir / "writer.lock"

    @contextmanager
    def _writer(self):
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._lock, self.lock_file.open("a+b") as lock:
            os.chmod(self.lock_file, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def bootstrap(self) -> dict:
        with self._writer():
            self._journal_key()
            if os.path.lexists(self.journal_file):
                self._recover()
            match = SUPPORTED_VERSION.fullmatch(str(self.mita.version()).strip())
            if not match:
                raise ConfigConflict("only mita v3.35.x is supported")
            observed = self.mita.observe()
            validate_config(observed, elevated=True)
            if self.state_file.exists():
                state = self._state()
                if state["config_hash"] != _hash(observed):
                    raise ConfigConflict("observed config changed outside manager")
            else:
                state = {
                    "version": 2,
                    "generation": 0,
                    "revision": _hash(observed),
                    "config_hash": _hash(observed),
                    "disabled": {},
                    "tombstones": [],
                    "metric_baselines": {},
                }
                _atomic(self.state_file, state)
            return {
                "ready": self.mita.status() == "RUNNING",
                "version": match.group(1),
                "revision": state["revision"],
            }

    def _journal_key(self) -> bytes:
        if not os.path.lexists(self.journal_key_file):
            if os.path.lexists(self.journal_file):
                raise ConfigConflict("transaction recovery authentication unavailable")
            _atomic(self.journal_key_file, secrets.token_bytes(32))
        key = _read_secure(self.journal_key_file, max_size=32)
        if len(key) != 32:
            raise ConfigConflict("invalid transaction recovery authentication")
        return key

    def _write_journal(self, journal: dict) -> None:
        authenticated = dict(journal)
        authenticated.pop("mac", None)
        authenticated["mac"] = hmac.new(
            self._journal_key(), _canonical(authenticated), hashlib.sha256
        ).hexdigest()
        _atomic(self.journal_file, authenticated)

    def _state(self) -> dict:
        info = self.state_file.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ConfigConflict("unsafe manager state")
        try:
            state = json.loads(self.state_file.read_text())
        except (OSError, ValueError) as exc:
            raise ConfigConflict("invalid manager state") from exc
        if (
            not isinstance(state, dict)
            or set(state)
            != {
                "version",
                "generation",
                "revision",
                "config_hash",
                "disabled",
                "tombstones",
                "metric_baselines",
            }
            or state["version"] != 2
            or isinstance(state["generation"], bool)
            or not isinstance(state["generation"], int)
            or state["generation"] < 0
        ):
            raise ConfigConflict("invalid manager state")
        return state

    def inspect(self) -> dict:
        with self._writer():
            state = self._state()
            observed = self.mita.observe()
            validate_config(observed, elevated=True)
            if _hash(observed) != state["config_hash"]:
                raise ConfigConflict("observed config changed outside manager")
            status = self.mita.status().upper()
            return {
                "revision": state["revision"],
                "ready": status == "RUNNING",
                "status": status.lower(),
            }

    def _wait_status(self, target: str, error: str) -> str:
        deadline = time.monotonic() + self.status_timeout
        while True:
            status = self.mita.status().upper()
            if status == target:
                return status
            if status not in {"STARTING", "STOPPING"} or time.monotonic() >= deadline:
                raise MitaError(error)
            time.sleep(
                min(self.status_poll_interval, max(0, deadline - time.monotonic()))
            )

    def lifecycle(self, action: str) -> dict:
        if action not in {"start", "stop", "restart"}:
            raise ValidationError("invalid lifecycle action")
        with self._writer():
            state = self._state()
            before = self.mita.observe()
            validate_config(before, elevated=True)
            if _hash(before) != state["config_hash"]:
                raise ConfigConflict("observed config changed outside manager")
            if action == "stop":
                self.mita.stop()
            else:
                if action == "restart":
                    self.mita.stop()
                    self._wait_status("IDLE", "mita failed to reach idle state")
                self.mita.start()
            after = self.mita.observe()
            validate_config(after, elevated=True)
            if _hash(after) != state["config_hash"]:
                raise ConfigConflict("lifecycle changed observed configuration")
            if action == "stop":
                status = self._wait_status("IDLE", "mita failed to reach idle state")
            else:
                status = self._wait_status(
                    "RUNNING", "mita failed to reach running state"
                )
                self.protocol_probe()
            return {
                "revision": state["revision"],
                "ready": status == "RUNNING",
                "status": status.lower(),
            }

    def list_users(self) -> list[dict]:
        with self._writer():
            state = self._state()
            config = self.mita.observe()
            rows = [
                {
                    "username": row["name"],
                    "enabled": True,
                    "quotas": copy.deepcopy(row.get("quotas", [])),
                }
                for row in config.get("users", [])
            ]
            rows.extend(
                {
                    "username": name,
                    "enabled": False,
                    "quotas": copy.deepcopy(row.get("quotas", [])),
                }
                for name, row in state["disabled"].items()
            )
            return sorted(rows, key=lambda row: row["username"])

    @staticmethod
    def _expected(config: dict) -> dict:
        result = copy.deepcopy(config)
        for user in result.get("users", []):
            # A readback keeps the blanked password beside the stored hash, so only a
            # freshly supplied password is hashed here; re-hashing the empty one would
            # replace every earlier user's credential and fail the readback check.
            if user.get("password"):
                raw = user["password"]
                user["password"] = ""
                user["hashedPassword"] = hashlib.sha256(
                    (raw + "\0" + user["name"]).encode()
                ).hexdigest()
            # mita's protobuf JSON renderer omits an empty repeated quota field.
            if user.get("quotas") == []:
                user.pop("quotas")
        return result

    def _check_revision(self, state: dict, expected: str) -> None:
        if not isinstance(expected, str) or not secrets.compare_digest(
            state["revision"], expected
        ):
            raise ConfigConflict("desired revision does not match")

    def _transaction(
        self, desired: dict, state: dict, *, mode: str, operation: str
    ) -> str:
        if mode not in {"reload", "restart"} or operation not in TRANSACTION_MODES:
            raise ValidationError("invalid transaction metadata")
        validate_config(desired, elevated=True)
        before = self.mita.observe()
        validate_config(before, elevated=True)
        expected = self._expected(desired)
        if mode != _transaction_mode(operation, before, expected):
            raise ValidationError("invalid transaction metadata")
        previous_hash = _hash(before)
        if previous_hash != state["config_hash"]:
            raise ConfigConflict("observed config changed outside manager")
        desired_hash = _hash(expected)
        next_generation = state["generation"] + 1
        next_revision = _hash(
            {
                "config": expected,
                "disabled": state["disabled"],
                "tombstones": state["tombstones"],
                "generation": next_generation,
            }
        )
        self.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        backup = self.backup_dir / f"g{state['generation']}-{state['revision']}.json"
        _atomic(backup, before)
        backup_data = _read_secure(backup, max_size=self.mita.max_output if hasattr(self.mita, "max_output") else 1_048_576)
        journal = {
            "version": 3,
            "schema": "mieru-transaction-journal-v3",
            "phase": "prepared",
            "operation": operation,
            "mode": mode,
            "previous_config_hash": previous_hash,
            "desired_config_hash": desired_hash,
            "state_revision": state["revision"],
            "state_generation": state["generation"],
            "next_revision": next_revision,
            "next_generation": next_generation,
            "backup_basename": backup.name,
            "backup_size": len(backup_data),
            "backup_sha256": hashlib.sha256(backup_data).hexdigest(),
        }
        self._write_journal(journal)
        try:
            self.mita.apply(desired)
            journal["phase"] = "applied"
            self._write_journal(journal)
            observed = self.mita.observe()
            if _hash(observed) != desired_hash:
                raise MitaError("mita readback mismatch")
            if mode == "reload":
                self.mita.reload()
            else:
                self.mita.stop()
                self._wait_status("IDLE", "mita failed to reach idle state")
                self.mita.start()
            self._wait_status("RUNNING", "mita failed to reach running state")
            self.protocol_probe()
        except BaseException as exc:
            try:
                self.mita.apply(before)
                journal["phase"] = "rollback_applied"
                self._write_journal(journal)
                self.mita.stop()
                self._wait_status("IDLE", "rollback failed to reach idle state")
                self.mita.start()
                self._wait_status("RUNNING", "rollback status failed")
                self.protocol_probe()
            except BaseException as rollback_error:
                raise MitaError(
                    "transaction rollback requires recovery"
                ) from rollback_error
            self.journal_file.unlink(missing_ok=True)
            _fsync_dir(self.state_dir)
            raise MitaError("transaction failed and was rolled back") from exc
        state["config_hash"] = desired_hash
        state["revision"] = next_revision
        state["generation"] = next_generation
        _atomic(self.state_file, state)
        self.journal_file.unlink(missing_ok=True)
        _fsync_dir(self.state_dir)
        return state["revision"]

    def _recover(self) -> None:
        try:
            key = self._journal_key()
            raw = _read_secure(self.journal_file, max_size=65_536)
            journal = json.loads(raw)
            fields = {
                "version",
                "schema",
                "phase",
                "operation",
                "mode",
                "previous_config_hash",
                "desired_config_hash",
                "state_revision",
                "state_generation",
                "next_revision",
                "next_generation",
                "backup_basename",
                "backup_size",
                "backup_sha256",
                "mac",
            }
            if (
                not isinstance(journal, dict)
                or set(journal) != fields
                or not isinstance(journal["mac"], str)
                or re.fullmatch(r"[0-9a-f]{64}", journal["mac"]) is None
            ):
                raise ValueError("invalid journal")
            unsigned = {name: value for name, value in journal.items() if name != "mac"}
            expected_mac = hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()
            if not secrets.compare_digest(journal["mac"], expected_mac):
                raise ValueError("journal authentication failed")
            if (
                journal["version"] != 3
                or journal["schema"] != "mieru-transaction-journal-v3"
                or journal["phase"] not in {"prepared", "applied", "rollback_applied"}
                or journal["mode"] not in {"reload", "restart"}
                or journal["operation"] not in TRANSACTION_MODES
                or journal["backup_basename"]
                != f"g{journal['state_generation']}-{journal['state_revision']}.json"
                or not re.fullmatch(r"[0-9a-f]{64}", journal["previous_config_hash"])
                or not re.fullmatch(r"[0-9a-f]{64}", journal["desired_config_hash"])
                or not re.fullmatch(r"[0-9a-f]{64}", journal["state_revision"])
                or not re.fullmatch(r"[0-9a-f]{64}", journal["next_revision"])
                or isinstance(journal["state_generation"], bool)
                or not isinstance(journal["state_generation"], int)
                or journal["state_generation"] < 0
                or journal["next_generation"] != journal["state_generation"] + 1
                or isinstance(journal["backup_size"], bool)
                or not isinstance(journal["backup_size"], int)
                or journal["backup_size"] < 1
                or not re.fullmatch(r"[0-9a-f]{64}", journal["backup_sha256"])
            ):
                raise ValueError("invalid journal")
            state = self._state()
            observed = self.mita.observe()
            observed_hash = _hash(observed)
            if (
                state["generation"] == journal["next_generation"]
                and state["revision"] == journal["next_revision"]
                and state["config_hash"] == journal["desired_config_hash"]
                and observed_hash == journal["desired_config_hash"]
            ):
                self.journal_file.unlink()
                _fsync_dir(self.state_dir)
                return
            if (
                state["generation"] != journal["state_generation"]
                or state["revision"] != journal["state_revision"]
                or state["config_hash"] != journal["previous_config_hash"]
            ):
                raise ValueError("journal generation is stale")
            phase_hashes = {
                "prepared": {
                    journal["previous_config_hash"],
                    journal["desired_config_hash"],
                },
                "applied": {journal["desired_config_hash"]},
                "rollback_applied": {journal["previous_config_hash"]},
            }
            if observed_hash not in phase_hashes[journal["phase"]]:
                raise ValueError("observed config does not match journal phase")
            backup = self.backup_dir / journal["backup_basename"]
            if backup.parent != self.backup_dir:
                raise ValueError("backup escapes state")
            backup_data = _read_secure(backup, max_size=1_048_576)
            if (
                len(backup_data) != journal["backup_size"]
                or not secrets.compare_digest(
                    hashlib.sha256(backup_data).hexdigest(), journal["backup_sha256"]
                )
            ):
                raise ValueError("backup digest mismatch")
            config = json.loads(backup_data)
            validate_config(config, elevated=True)
            if _hash(config) != journal["previous_config_hash"]:
                raise ValueError("backup config mismatch")
            if journal["state_revision"] != state["revision"]:
                raise ValueError("journal state revision mismatch")
            if observed_hash == journal["desired_config_hash"]:
                if journal["mode"] != _transaction_mode(
                    journal["operation"], config, observed
                ):
                    raise ValueError("journal mode mismatch")
                canonical_next_revision = _hash(
                    {
                        "config": observed,
                        "disabled": state["disabled"],
                        "tombstones": state["tombstones"],
                        "generation": journal["next_generation"],
                    }
                )
                if journal["next_revision"] != canonical_next_revision:
                    raise ValueError("journal next revision mismatch")
            if observed_hash != journal["previous_config_hash"]:
                self.mita.apply(config)
            self.mita.stop()
            self._wait_status("IDLE", "recovery failed to reach idle state")
            self.mita.start()
            self._wait_status("RUNNING", "recovery status failed")
            self.protocol_probe()
            if _hash(self.mita.observe()) != journal["previous_config_hash"]:
                raise MitaError("recovery readback mismatch")
            self.journal_file.unlink()
            _fsync_dir(self.state_dir)
        except BaseException as exc:
            raise ConfigConflict("transaction recovery failed") from exc

    def _find_active(self, config: dict, username: str) -> tuple[int, dict]:
        for index, row in enumerate(config.get("users", [])):
            if row.get("name") == username:
                return index, row
        raise ConfigConflict("user not found")

    def create_user(
        self,
        username: str,
        quotas: list[dict],
        *,
        expected_revision: str,
        elevated: bool = False,
        allow_private_ip: bool = False,
        allow_loopback_ip: bool = False,
    ) -> dict:
        with self._writer():
            if (
                not isinstance(username, str)
                or not username
                or len(username.encode()) > 64
            ):
                raise ValidationError("invalid username")
            state = self._state()
            self._check_revision(state, expected_revision)
            if username in state["tombstones"]:
                raise ConfigConflict("username reuse is forbidden")
            config = self.mita.observe()
            if (
                any(row.get("name") == username for row in config.get("users", []))
                or username in state["disabled"]
            ):
                raise ConfigConflict("user already exists")
            if (allow_private_ip or allow_loopback_ip) and not elevated:
                raise ValidationError(
                    "private/loopback SSRF flags require elevated approval"
                )
            raw = secrets.token_urlsafe(24)
            user = {"name": username, "password": raw, "quotas": copy.deepcopy(quotas)}
            if allow_private_ip:
                user["allowPrivateIP"] = True
            if allow_loopback_ip:
                user["allowLoopbackIP"] = True
            config.setdefault("users", []).append(user)
            share_url = self._share(username, raw, config)
            mode = "restart" if allow_private_ip or allow_loopback_ip else "reload"
            revision = self._transaction(
                config, state, mode=mode, operation="user.create"
            )
            return {
                "username": username,
                "share_url": share_url,
                "revision": revision,
            }

    def disable_user(self, username: str, *, expected_revision: str) -> dict:
        with self._writer():
            state = self._state()
            self._check_revision(state, expected_revision)
            config = self.mita.observe()
            index, row = self._find_active(config, username)
            state["disabled"][username] = copy.deepcopy(row)
            config["users"].pop(index)
            return {
                "username": username,
                "enabled": False,
                "revision": self._transaction(
                    config, state, mode="restart", operation="user.disable"
                ),
            }

    def enable_user(self, username: str, *, expected_revision: str) -> dict:
        with self._writer():
            state = self._state()
            self._check_revision(state, expected_revision)
            if username not in state["disabled"]:
                raise ConfigConflict("user not found")
            config = self.mita.observe()
            config.setdefault("users", []).append(state["disabled"].pop(username))
            return {
                "username": username,
                "enabled": True,
                "revision": self._transaction(
                    config, state, mode="restart", operation="user.enable"
                ),
            }

    def rotate_user(self, username: str, *, expected_revision: str) -> dict:
        with self._writer():
            state = self._state()
            self._check_revision(state, expected_revision)
            config = self.mita.observe()
            index, old = self._find_active(config, username)
            raw = secrets.token_urlsafe(24)
            config["users"][index] = {
                key: copy.deepcopy(value)
                for key, value in old.items()
                if key != "hashedPassword"
            }
            config["users"][index]["password"] = raw
            share_url = self._share(username, raw, config)
            revision = self._transaction(
                config, state, mode="restart", operation="user.rotate"
            )
            return {
                "username": username,
                "share_url": share_url,
                "revision": revision,
            }

    def delete_user(self, username: str, *, expected_revision: str) -> dict:
        with self._writer():
            state = self._state()
            self._check_revision(state, expected_revision)
            config = self.mita.observe()
            if username in state["disabled"]:
                state["disabled"].pop(username)
            else:
                index, _ = self._find_active(config, username)
                config["users"].pop(index)
            state["tombstones"].append(username)
            return {
                "username": username,
                "revision": self._transaction(
                    config, state, mode="restart", operation="user.delete"
                ),
            }

    def set_quotas(
        self, username: str, quotas: list[dict], *, expected_revision: str
    ) -> dict:
        with self._writer():
            state = self._state()
            self._check_revision(state, expected_revision)
            config = self.mita.observe()
            _, row = self._find_active(config, username)
            row["quotas"] = copy.deepcopy(quotas)
            return {
                "username": username,
                "revision": self._transaction(
                    config, state, mode="reload", operation="user.quotas"
                ),
            }

    def _share(self, username: str, password: str, config: dict) -> str:
        if "trafficPattern" in config:
            raise ValidationError(
                "share-link creation is unavailable for trafficPattern configurations"
            )
        query: list[tuple[str, str]] = [("profile", username)]
        for binding in config["portBindings"]:
            query.extend(
                (
                    ("port", str(binding.get("port", binding.get("portRange")))),
                    ("protocol", binding["protocol"]),
                )
            )
        query.append(("mtu", str(config.get("mtu", 1400))))
        host = self.public_host
        try:
            if ipaddress.ip_address(host).version == 6:
                host = f"[{host}]"
        except ValueError:
            pass
        return f"mierus://{quote(username, safe='')}:{quote(password, safe='')}@{host}?{urlencode(query)}"

    def metrics(self) -> dict:
        with self._writer():
            return {
                "status": "error",
                "stale": True,
                "users": [],
                "capability": "unavailable",
                "reason": "typed_histories_unavailable",
            }

    def reset_metric_baseline(self, username: str) -> dict:
        with self._writer():
            raise ConfigConflict("per-user Mieru metrics capability is unavailable")
