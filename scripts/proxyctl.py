#!/usr/bin/env python3
"""Fail-closed host auditor and owned Nginx SNI route transaction manager."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

OWNERSHIP_BEGIN = "# BEGIN PROXY-CONTROL ROUTES"
OWNERSHIP_END = "# END PROXY-CONTROL ROUTES"
STATE_PATH = "/var/lib/proxy-control/ownership.json"
STATE_SCHEMA = 1
DOMAIN_RE = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class InstallerConflict(RuntimeError):
    """A condition that cannot be changed safely or unambiguously."""


def validate_domain(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(normalized):
        raise ValueError("a plain fully-qualified domain name is required")
    return normalized


@dataclass(frozen=True)
class DomainAudit:
    domain: str
    a_records: list[str]
    aaaa_records: list[str]
    dns_matches_host: bool
    unhandled_aaaa: bool
    tls_certificate_present: bool


@dataclass(frozen=True)
class NginxAudit:
    installed: bool
    stream_enabled: bool
    sni_routes: dict[str, str]
    http_domains: list[str]
    config_files: list[str]
    sni_map_count: int = 0
    sni_map_files: dict[str, int] = field(default_factory=dict)
    duplicate_sni_domains: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class XrayAudit:
    installed: bool
    inbounds: list[dict]
    outbound_tags: list[str]


@dataclass(frozen=True)
class AuditReport:
    nginx: NginxAudit
    xray: XrayAudit
    docker_available: bool
    listening_ports: list[int]
    listener_owners: dict[int, list[str]] = field(default_factory=dict)
    domains: list[DomainAudit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _root_path(root: Path, absolute: str) -> Path:
    if not absolute.startswith("/"):
        raise InstallerConflict("host paths must be absolute")
    return root / absolute.lstrip("/")


def _host_path(root: Path, path: Path) -> str:
    try:
        return "/" + str(path.relative_to(root))
    except ValueError as exc:
        raise InstallerConflict("resolved path escapes the selected root") from exc


def _read_text(path: Path) -> str:
    try:
        return path.read_text()
    except (FileNotFoundError, PermissionError, OSError, UnicodeError):
        return ""


def _nginx_files(root: Path) -> list[Path]:
    candidates = [_root_path(root, "/etc/nginx/nginx.conf")]
    for directory in ("/etc/nginx/stream.d", "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"):
        folder = _root_path(root, directory)
        if folder.is_dir():
            candidates.extend(sorted(path for path in folder.iterdir() if path.is_file()))
    unique: list[Path] = []
    seen: set[tuple[int, int]] = set()
    for path in candidates:
        if not path.is_file():
            continue
        metadata = path.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        if identity not in seen:
            seen.add(identity)
            unique.append(path)
    return unique


def _parse_sni_entries(text: str) -> list[tuple[str, str]]:
    return [
        (domain.lower(), backend)
        for domain, backend in re.findall(
            r"(?<![A-Za-z0-9_.-])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\s+"
            r"((?:127\.0\.0\.1|\[?::1\]?):\d+)\s*;",
            text,
        )
    ]


def _parse_sni_routes(text: str) -> dict[str, str]:
    return dict(_parse_sni_entries(text))


def _parse_http_domains(text: str) -> set[str]:
    domains: set[str] = set()
    for match in re.finditer(r"(?m)^\s*server_name\s+([^;]+);", text):
        for value in match.group(1).split():
            try:
                domains.add(validate_domain(value))
            except ValueError:
                continue
    return domains


def _xray_audit(root: Path) -> XrayAudit:
    path = _root_path(root, "/usr/local/x-ui/bin/config.json")
    if not path.is_file():
        return XrayAudit(False, [], [])
    try:
        config = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return XrayAudit(True, [], [])
    inbounds = []
    for inbound in config.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        stream = inbound.get("streamSettings") if isinstance(inbound.get("streamSettings"), dict) else {}
        reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
        names = reality.get("serverNames") if isinstance(reality.get("serverNames"), list) else []
        inbounds.append({
            "tag": inbound.get("tag"),
            "protocol": inbound.get("protocol"),
            "listen": inbound.get("listen"),
            "port": inbound.get("port"),
            "security": stream.get("security"),
            "server_names": sorted(name for name in names if isinstance(name, str)),
        })
    tags = [item.get("tag") for item in config.get("outbounds", []) if isinstance(item, dict)]
    return XrayAudit(True, inbounds, sorted(tag for tag in tags if isinstance(tag, str)))


def _resolve_domain(domain: str) -> dict[str, list[str]]:
    records = {"A": set(), "AAAA": set()}
    try:
        answers = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        answers = []
    for family, _kind, _proto, _canon, address in answers:
        if family == socket.AF_INET:
            records["A"].add(address[0])
        elif family == socket.AF_INET6:
            records["AAAA"].add(address[0])
    return {key: sorted(value) for key, value in records.items()}


def _local_addresses() -> set[str]:
    addresses: set[str] = set()
    result = subprocess.run(["ip", "-j", "address"], capture_output=True, text=True, check=False)
    try:
        links = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return addresses
    for link in links:
        for item in link.get("addr_info", []):
            if item.get("scope") in {"global", "host"} and isinstance(item.get("local"), str):
                addresses.add(item["local"])
    return addresses


def _certificate_names(root: Path, domains: set[str]) -> set[str]:
    present = set()
    for domain in domains:
        cert = _root_path(root, f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        if not cert.is_file():
            continue
        try:
            decoded = ssl._ssl._test_decode_cert(str(cert))  # noqa: SLF001
        except (OSError, ssl.SSLError, ValueError):
            continue
        names = {value.lower() for kind, value in decoded.get("subjectAltName", []) if kind == "DNS"}
        if domain in names:
            present.add(domain)
    return present


def audit_host(
    *,
    root: Path = Path("/"),
    listening_ports: set[int] | None = None,
    listener_owners: dict[int, list[str]] | None = None,
    docker_available: bool | None = None,
    dns_records: dict[str, dict[str, list[str]]] | None = None,
    local_addresses: set[str] | None = None,
    tls_names: set[str] | None = None,
    domains: set[str] | None = None,
) -> AuditReport:
    """Collect facts only. No file, service, package, firewall, or DNS mutation occurs."""
    files = _nginx_files(root)
    texts = {path: _read_text(path) for path in files}
    nginx_main = _read_text(_root_path(root, "/etc/nginx/nginx.conf"))
    route_values: dict[str, set[str]] = {}
    route_counts: dict[str, int] = {}
    http_domains: set[str] = set()
    map_files: dict[str, int] = {}
    for path, text in texts.items():
        count = len(_map_blocks(text))
        if count:
            map_files[_host_path(root, path)] = count
        for domain, backend in _parse_sni_entries(text):
            route_values.setdefault(domain, set()).add(backend)
            route_counts[domain] = route_counts.get(domain, 0) + 1
        http_domains.update(_parse_http_domains(text))
    routes = {domain: sorted(backends)[0] for domain, backends in route_values.items()}
    duplicates = sorted(domain for domain, count in route_counts.items() if count > 1)
    if listening_ports is None or listener_owners is None:
        detected_ports, detected_owners = _listener_inventory()
        if listening_ports is None:
            listening_ports = detected_ports
        if listener_owners is None:
            listener_owners = detected_owners
    if docker_available is None:
        docker_available = shutil.which("docker") is not None

    requested = set(domains or ()) | set((dns_records or {}).keys())
    records = dns_records if dns_records is not None else {name: _resolve_domain(name) for name in requested}
    local = _local_addresses() if local_addresses is None else local_addresses
    cert_names = _certificate_names(root, requested) if tls_names is None else tls_names
    domain_audits = []
    for domain in sorted(validate_domain(name) for name in requested):
        record = records.get(domain, {})
        a_records = sorted(set(record.get("A", [])))
        aaaa_records = sorted(set(record.get("AAAA", [])))
        domain_audits.append(DomainAudit(
            domain=domain,
            a_records=a_records,
            aaaa_records=aaaa_records,
            dns_matches_host=bool(set(a_records) & local),
            unhandled_aaaa=bool(aaaa_records and not set(aaaa_records) <= local),
            tls_certificate_present=domain in cert_names,
        ))

    return AuditReport(
        nginx=NginxAudit(
            installed=bool(files),
            stream_enabled=bool(re.search(r"(?m)^\s*stream\s*\{", nginx_main)),
            sni_routes=dict(sorted(routes.items())),
            http_domains=sorted(http_domains),
            config_files=[_host_path(root, path) for path in files],
            sni_map_count=sum(map_files.values()),
            sni_map_files=dict(sorted(map_files.items())),
            duplicate_sni_domains=duplicates,
        ),
        xray=_xray_audit(root),
        docker_available=docker_available,
        listening_ports=sorted(listening_ports),
        listener_owners={port: sorted(set(names)) for port, names in sorted(listener_owners.items())},
        domains=domain_audits,
    )


def _listener_inventory() -> tuple[set[int], dict[int, list[str]]]:
    result = subprocess.run(["ss", "-H", "-lntp"], capture_output=True, text=True, check=False)
    ports: set[int] = set()
    owners: dict[int, list[str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        endpoint = fields[3] if len(fields) > 3 else ""
        match = re.search(r":(\d+)$", endpoint)
        if match:
            port = int(match.group(1))
            ports.add(port)
            names = re.findall(r'users:\(\("([^"\\]+)"', line)
            if names:
                owners.setdefault(port, []).extend(names)
    return ports, owners


def _listening_ports() -> set[int]:
    return _listener_inventory()[0]


def _map_blocks(text: str) -> list[tuple[int, int]]:
    blocks = []
    pattern = re.compile(r"map\s+\$ssl_preread_server_name\s+\$[A-Za-z0-9_]+\s*\{")
    for match in pattern.finditer(text):
        depth = 0
        for index in range(match.end() - 1, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((match.start(), index + 1))
                    break
        else:
            raise InstallerConflict("unterminated SNI map")
    return blocks


def patch_stream_map(
    text: str,
    *,
    proxy_domain: str,
    panel_domain: str,
    proxy_backend: str,
    panel_backend: str,
    ownership_id: str | None = None,
) -> str:
    proxy_domain, panel_domain = validate_domain(proxy_domain), validate_domain(panel_domain)
    if proxy_domain == panel_domain:
        raise InstallerConflict("proxy and panel domains must differ")
    blocks = _map_blocks(text)
    if len(blocks) != 1:
        raise InstallerConflict("exactly one SNI map is required")
    start, end = blocks[0]
    block = text[start:end]
    wanted = {proxy_domain: proxy_backend, panel_domain: panel_backend}
    existing = _parse_sni_routes(block)
    for domain, backend in wanted.items():
        if domain in existing and backend != existing[domain]:
            raise InstallerConflict(f"domain already routed: {domain}")
    suffix = f" {ownership_id}" if ownership_id else ""
    begin, finish = OWNERSHIP_BEGIN + suffix, OWNERSHIP_END + suffix
    managed = (
        f"    {begin}\n"
        f"    {proxy_domain} {proxy_backend};\n"
        f"    {panel_domain} {panel_backend};\n"
        f"    {finish}\n"
    )
    begins, ends = block.count(OWNERSHIP_BEGIN), block.count(OWNERSHIP_END)
    if (begins, ends) == (1, 1):
        marker_start = block.index(OWNERSHIP_BEGIN)
        marker_end = block.index("\n", block.index(OWNERSHIP_END, marker_start))
        current = block[marker_start:marker_end]
        expected = managed.strip()
        def normalize(value: str) -> str:
            return "\n".join(line.strip() for line in value.splitlines())

        if normalize(current) != normalize(expected):
            raise InstallerConflict("owned route block differs from requested configuration")
        return text
    if (begins, ends) != (0, 0):
        raise InstallerConflict("malformed ownership markers")
    default_match = re.search(r"(?m)^\s*default\s+[^;]+;", block)
    if default_match is None:
        raise InstallerConflict("SNI map has no default route")
    insert_at = start + default_match.start()
    return text[:insert_at] + managed + text[insert_at:]


@dataclass(frozen=True)
class InstallPlan:
    proxy_domain: str
    panel_domain: str
    route_file: str = "/etc/nginx/stream.d/routes.conf"
    proxy_backend_port: int = 8445
    panel_backend_port: int = 8787
    schema: int = 1

    @property
    def proxy_backend(self) -> str:
        return f"127.0.0.1:{self.proxy_backend_port}"

    @property
    def panel_backend(self) -> str:
        return f"127.0.0.1:{self.panel_backend_port}"

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "proxy_domain": self.proxy_domain,
            "panel_domain": self.panel_domain,
            "proxy_backend": self.proxy_backend,
            "panel_backend": self.panel_backend,
            "route_file": self.route_file,
            "actions": [
                {"kind": "nginx_route", "target": self.route_file},
                {"kind": "ownership_manifest", "target": STATE_PATH},
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_audit(
        cls,
        report: AuditReport,
        *,
        proxy_domain: str,
        panel_domain: str,
        route_file: str = "/etc/nginx/stream.d/routes.conf",
        proxy_backend_port: int = 8445,
        panel_backend_port: int = 8787,
        require_domain_preflight: bool = True,
    ) -> "InstallPlan":
        proxy_domain, panel_domain = validate_domain(proxy_domain), validate_domain(panel_domain)
        if proxy_domain == panel_domain:
            raise InstallerConflict("proxy and panel domains must differ")
        if not route_file.startswith("/") or ".." in Path(route_file).parts:
            raise InstallerConflict("route file must be a normalized absolute path")
        known = set(report.nginx.sni_routes) | set(report.nginx.http_domains)
        for domain in (proxy_domain, panel_domain):
            if domain in known:
                raise InstallerConflict(f"domain already routed: {domain}")
        if report.nginx.duplicate_sni_domains:
            raise InstallerConflict("duplicate SNI routes make the topology ambiguous")
        if report.nginx.stream_enabled and report.nginx.sni_map_count != 1:
            raise InstallerConflict("exactly one SNI map is required")
        for port in (proxy_backend_port, panel_backend_port):
            if not 1024 <= port <= 65535:
                raise InstallerConflict(f"backend port {port} is outside 1024..65535")
            if port in report.listening_ports:
                raise InstallerConflict(f"backend port {port} is already listening")
        if not report.nginx.stream_enabled and 443 in report.listening_ports:
            raise InstallerConflict("public 443 is occupied without an Nginx stream router")
        owners_443 = report.listener_owners.get(443, [])
        if report.nginx.stream_enabled and owners_443 and not any("nginx" in name.lower() for name in owners_443):
            raise InstallerConflict("public 443 is not owned by Nginx despite a stream configuration")
        if not report.docker_available:
            raise InstallerConflict("Docker is unavailable")
        if report.nginx.stream_enabled and report.nginx.sni_map_files.get(route_file) != 1:
            raise InstallerConflict("route file is not the single audited SNI map file")
        if require_domain_preflight:
            checks = {item.domain: item for item in report.domains}
            if set(checks) != {proxy_domain, panel_domain}:
                raise InstallerConflict("domain preflight evidence is incomplete")
            for domain in (proxy_domain, panel_domain):
                check = checks.get(domain)
                if check is None or not check.dns_matches_host:
                    raise InstallerConflict(f"DNS does not resolve to this host: {domain}")
                if check.unhandled_aaaa:
                    raise InstallerConflict(f"unhandled AAAA record: {domain}")
                if not check.tls_certificate_present:
                    raise InstallerConflict(f"TLS certificate is missing or does not cover: {domain}")
        return cls(proxy_domain, panel_domain, route_file, proxy_backend_port, panel_backend_port)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_parent(path: Path) -> None:
    missing = []
    cursor = path.parent
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        directory.mkdir()
        _fsync_dir(directory.parent)


def _atomic_write(path: Path, data: bytes, *, mode: int, owner: tuple[int, int] | None = None) -> None:
    _ensure_parent(path)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if owner is not None:
            os.chown(tmp, *owner)
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def _state_path(root: Path) -> Path:
    return _root_path(root, STATE_PATH)


def _write_state(path: Path, state: dict) -> None:
    _atomic_write(path, (json.dumps(state, indent=2, sort_keys=True) + "\n").encode(), mode=0o600)


def _validate_manifest_plan(plan: object) -> None:
    if not isinstance(plan, dict):
        raise InstallerConflict("ownership manifest plan is invalid")
    required = {
        "schema", "proxy_domain", "panel_domain", "proxy_backend", "panel_backend",
        "route_file", "actions",
    }
    if set(plan) != required or plan.get("schema") != 1:
        raise InstallerConflict("ownership manifest plan is invalid")
    try:
        proxy_domain = validate_domain(plan["proxy_domain"])
        panel_domain = validate_domain(plan["panel_domain"])
    except (TypeError, ValueError) as exc:
        raise InstallerConflict("ownership manifest plan is invalid") from exc
    if proxy_domain == panel_domain:
        raise InstallerConflict("ownership manifest plan is invalid")
    route_file = plan["route_file"]
    if not isinstance(route_file, str) or not route_file.startswith("/") or ".." in Path(route_file).parts:
        raise InstallerConflict("ownership manifest plan is invalid")
    for key in ("proxy_backend", "panel_backend"):
        if not isinstance(plan[key], str) or not re.fullmatch(r"127\.0\.0\.1:(\d{4,5})", plan[key]):
            raise InstallerConflict("ownership manifest plan is invalid")
        port = int(plan[key].rsplit(":", 1)[1])
        if not 1024 <= port <= 65535:
            raise InstallerConflict("ownership manifest plan is invalid")
    expected_actions = [
        {"kind": "nginx_route", "target": route_file},
        {"kind": "ownership_manifest", "target": STATE_PATH},
    ]
    if plan["actions"] != expected_actions:
        raise InstallerConflict("ownership manifest plan is invalid")


def _load_state(root: Path) -> tuple[Path, dict] | None:
    path = _state_path(root)
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallerConflict("ownership manifest is unreadable") from exc
    required = {
        "schema", "install_id", "status", "route_file", "backup_file", "route_mode",
        "route_uid", "route_gid", "route_sha256_before", "route_sha256_owned", "plan",
    }
    if set(state) != required or state.get("schema") != STATE_SCHEMA:
        raise InstallerConflict("ownership manifest schema is invalid")
    if state["status"] not in {"applying", "active", "uninstalling"}:
        raise InstallerConflict("ownership manifest status is invalid")
    install_id = state.get("install_id")
    if not isinstance(install_id, str) or not re.fullmatch(r"[0-9a-f]{32}", install_id):
        raise InstallerConflict("ownership manifest generation is invalid")
    for key in ("route_file", "backup_file"):
        if not isinstance(state[key], str) or not state[key].startswith("/") or ".." in Path(state[key]).parts:
            raise InstallerConflict("ownership manifest contains an unsafe path")
    expected_backup = f"/var/lib/proxy-control/backups/{install_id}.route"
    if state["backup_file"] != expected_backup:
        raise InstallerConflict("ownership manifest generation does not match its backup")
    for key in ("route_mode", "route_uid", "route_gid"):
        if isinstance(state[key], bool) or not isinstance(state[key], int) or state[key] < 0:
            raise InstallerConflict("ownership manifest metadata is invalid")
    if state["route_mode"] > 0o7777:
        raise InstallerConflict("ownership manifest metadata is invalid")
    _validate_manifest_plan(state["plan"])
    for key, label in (
        ("route_sha256_before", "original"),
        ("route_sha256_owned", "owned"),
    ):
        if not isinstance(state[key], str) or not re.fullmatch(r"[0-9a-f]{64}", state[key]):
            raise InstallerConflict(f"ownership manifest has an invalid {label} hash")
    return path, state


def _canonical_route(root: Path, route_file: str) -> tuple[Path, str]:
    supplied = _root_path(root, route_file)
    try:
        resolved = supplied.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise InstallerConflict(f"route file does not exist: {route_file}") from exc
    if not resolved.is_file():
        raise InstallerConflict(f"route file is not regular: {route_file}")
    return resolved, _host_path(root.resolve(), resolved)


def _run_nginx_validate() -> None:
    subprocess.run(["nginx", "-t"], check=True)


def _run_nginx_reload() -> None:
    subprocess.run(["systemctl", "reload", "nginx"], check=True)


@contextmanager
def _operation_lock(root: Path):
    lock_path = _root_path(root, "/run/lock/proxy-control.lock")
    _ensure_parent(lock_path)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "r+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallerConflict("another proxyctl operation is in progress") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _apply_plan_unlocked(
    plan: InstallPlan,
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> Path:
    loaded = _load_state(root)
    if loaded is not None:
        _path, state = loaded
        if state["status"] == "active" and state["plan"] == plan.to_dict():
            _repair_installation_unlocked(root=root, validate=validate, reload=reload)
            return _state_path(root)
        raise InstallerConflict("another owned installation or interrupted transaction exists")
    route, route_host_path = _canonical_route(root, plan.route_file)
    original = route.read_bytes()
    metadata = route.stat()
    install_id = uuid.uuid4().hex
    changed = patch_stream_map(
        original.decode(),
        proxy_domain=plan.proxy_domain,
        panel_domain=plan.panel_domain,
        proxy_backend=plan.proxy_backend,
        panel_backend=plan.panel_backend,
        ownership_id=install_id,
    ).encode()
    backup_host = f"/var/lib/proxy-control/backups/{install_id}.route"
    backup = _root_path(root, backup_host)
    _atomic_write(backup, original, mode=0o600)
    state = {
        "schema": STATE_SCHEMA,
        "install_id": install_id,
        "status": "applying",
        "route_file": route_host_path,
        "backup_file": backup_host,
        "route_mode": stat.S_IMODE(metadata.st_mode),
        "route_uid": metadata.st_uid,
        "route_gid": metadata.st_gid,
        "route_sha256_before": _sha256(original),
        "route_sha256_owned": _sha256(changed),
        "plan": plan.to_dict(),
    }
    manifest = _state_path(root)
    _write_state(manifest, state)
    try:
        _atomic_write(
            route,
            changed,
            mode=state["route_mode"],
            owner=(state["route_uid"], state["route_gid"]),
        )
        validate()
        reload()
        state["status"] = "active"
        _write_state(manifest, state)
    except BaseException:
        _atomic_write(
            route,
            original,
            mode=state["route_mode"],
            owner=(state["route_uid"], state["route_gid"]),
        )
        try:
            validate()
            reload()
        except BaseException:
            # Keep the durable applying journal and backup: repair can retry.
            raise
        manifest.unlink(missing_ok=True)
        _fsync_dir(manifest.parent)
        raise
    return manifest


def _repair_installation_unlocked(
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> None:
    loaded = _load_state(root)
    if loaded is None:
        return
    manifest, state = loaded
    route = _root_path(root, state["route_file"])
    backup = _root_path(root, state["backup_file"])
    if not route.is_file():
        raise InstallerConflict("owned route or backup is missing")
    current = route.read_bytes()
    if not backup.is_file():
        if state["status"] == "uninstalling" and _sha256(current) == state["route_sha256_before"]:
            validate()
            reload()
            manifest.unlink()
            _fsync_dir(manifest.parent)
            return
        raise InstallerConflict("owned route or backup is missing")
    original = backup.read_bytes()
    if _sha256(original) != state["route_sha256_before"]:
        raise InstallerConflict("owned backup has drifted")
    if state["status"] == "active":
        if _sha256(current) != state["route_sha256_owned"]:
            raise InstallerConflict("owned route file has drifted")
        validate()
        return
    if state["status"] == "applying":
        if _sha256(current) not in {state["route_sha256_before"], state["route_sha256_owned"]}:
            raise InstallerConflict("owned route file has drifted")
        _atomic_write(
            route,
            original,
            mode=state["route_mode"],
            owner=(state["route_uid"], state["route_gid"]),
        )
        validate()
        reload()
        manifest.unlink()
        _fsync_dir(manifest.parent)
        return
    if _sha256(current) == state["route_sha256_before"]:
        validate()
        reload()
        backup.unlink()
        _fsync_dir(backup.parent)
        manifest.unlink()
        _fsync_dir(manifest.parent)
        return
    if _sha256(current) == state["route_sha256_owned"]:
        state["status"] = "active"
        _write_state(manifest, state)
        validate()
        return
    raise InstallerConflict("owned route file has drifted")


def _uninstall_installation_unlocked(
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> None:
    loaded = _load_state(root)
    if loaded is None:
        return
    manifest, state = loaded
    if state["status"] != "active":
        raise InstallerConflict("repair the interrupted transaction before uninstall")
    route = _root_path(root, state["route_file"])
    backup = _root_path(root, state["backup_file"])
    if not route.is_file() or not backup.is_file():
        raise InstallerConflict("owned route or backup is missing")
    owned, original = route.read_bytes(), backup.read_bytes()
    if _sha256(owned) != state["route_sha256_owned"]:
        raise InstallerConflict("owned route file has drifted")
    if _sha256(original) != state["route_sha256_before"]:
        raise InstallerConflict("owned backup has drifted")
    state["status"] = "uninstalling"
    _write_state(manifest, state)
    try:
        _atomic_write(
            route,
            original,
            mode=state["route_mode"],
            owner=(state["route_uid"], state["route_gid"]),
        )
        validate()
        reload()
    except BaseException:
        _atomic_write(
            route,
            owned,
            mode=state["route_mode"],
            owner=(state["route_uid"], state["route_gid"]),
        )
        state["status"] = "active"
        _write_state(manifest, state)
        validate()
        reload()
        raise
    backup.unlink()
    _fsync_dir(backup.parent)
    manifest.unlink()
    _fsync_dir(manifest.parent)


def apply_plan(
    plan: InstallPlan,
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> Path:
    with _operation_lock(root):
        return _apply_plan_unlocked(plan, root=root, validate=validate, reload=reload)


def repair_installation(
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> None:
    with _operation_lock(root):
        _repair_installation_unlocked(root=root, validate=validate, reload=reload)


def uninstall_installation(
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> None:
    with _operation_lock(root):
        _uninstall_installation_unlocked(root=root, validate=validate, reload=reload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxyctl", description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="read-only host audit")
    audit.add_argument("--proxy-domain")
    audit.add_argument("--panel-domain")
    audit.add_argument("--json", action="store_true")
    for name in ("plan", "apply"):
        command = sub.add_parser(name, help=f"{name} a validated owned route transaction")
        command.add_argument("--proxy-domain", required=True)
        command.add_argument("--panel-domain", required=True)
        command.add_argument("--route-file", required=True)
        command.add_argument("--json", action="store_true")
    sub.add_parser("repair", help="idempotently recover or validate owned state")
    sub.add_parser("uninstall", help="transactionally remove only the owned route")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in {"repair", "uninstall"}:
            function = repair_installation if args.command == "repair" else uninstall_installation
            function(root=args.root)
            return 0
        requested = {
            validate_domain(value)
            for value in (getattr(args, "proxy_domain", None), getattr(args, "panel_domain", None))
            if value
        }
        report = audit_host(root=args.root, domains=requested)
        if args.command == "audit":
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) if args.json else report)
            return 0
        plan = InstallPlan.from_audit(
            report,
            proxy_domain=args.proxy_domain,
            panel_domain=args.panel_domain,
            route_file=args.route_file,
        )
        if args.command == "apply":
            apply_plan(plan, root=args.root)
        print(plan.to_json(), end="" if args.json else "")
        return 0
    except (InstallerConflict, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
