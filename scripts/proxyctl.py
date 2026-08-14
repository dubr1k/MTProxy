#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


OWNERSHIP_BEGIN = "# BEGIN PROXY-CONTROL ROUTES"
OWNERSHIP_END = "# END PROXY-CONTROL ROUTES"
DOMAIN_RE = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class InstallerConflict(RuntimeError):
    pass


def validate_domain(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(normalized):
        raise ValueError("a plain fully-qualified domain name is required")
    return normalized


@dataclass(frozen=True)
class NginxAudit:
    installed: bool
    stream_enabled: bool
    sni_routes: dict[str, str]
    http_domains: list[str]
    config_files: list[str]


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

    def to_dict(self) -> dict:
        return asdict(self)


def _root_path(root: Path, absolute: str) -> Path:
    return root / absolute.lstrip("/")


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
    return [path for path in candidates if path.is_file()]


def _parse_sni_routes(text: str) -> dict[str, str]:
    routes: dict[str, str] = {}
    for match in re.finditer(
        r"(?<![A-Za-z0-9_.-])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\s+"
        r"((?:127\.0\.0\.1|\[?::1\]?):\d+)\s*;",
        text,
    ):
        domain, backend = match.groups()
        routes[domain.lower()] = backend
    return routes


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
            "server_names": [name for name in names if isinstance(name, str)],
        })
    tags = [item.get("tag") for item in config.get("outbounds", []) if isinstance(item, dict)]
    return XrayAudit(True, inbounds, [tag for tag in tags if isinstance(tag, str)])


def audit_host(*, root: Path = Path("/"), listening_ports: set[int] | None = None,
               docker_available: bool | None = None) -> AuditReport:
    files = _nginx_files(root)
    texts = {path: _read_text(path) for path in files}
    nginx_main = _read_text(_root_path(root, "/etc/nginx/nginx.conf"))
    routes: dict[str, str] = {}
    http_domains: set[str] = set()
    for text in texts.values():
        routes.update(_parse_sni_routes(text))
        http_domains.update(_parse_http_domains(text))
    if listening_ports is None:
        listening_ports = _listening_ports()
    if docker_available is None:
        docker_available = shutil.which("docker") is not None
    return AuditReport(
        nginx=NginxAudit(
            installed=bool(files),
            stream_enabled=bool(re.search(r"(?m)^\s*stream\s*\{", nginx_main)),
            sni_routes=dict(sorted(routes.items())),
            http_domains=sorted(http_domains),
            config_files=["/" + str(path.relative_to(root)) for path in files],
        ),
        xray=_xray_audit(root),
        docker_available=docker_available,
        listening_ports=sorted(listening_ports),
    )


def _listening_ports() -> set[int]:
    result = subprocess.run(["ss", "-H", "-lnt"], capture_output=True, text=True, check=False)
    ports: set[int] = set()
    for line in result.stdout.splitlines():
        endpoint = line.split()[3] if len(line.split()) > 3 else ""
        match = re.search(r":(\d+)$", endpoint)
        if match:
            ports.add(int(match.group(1)))
    return ports


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


def patch_stream_map(text: str, *, proxy_domain: str, panel_domain: str,
                     proxy_backend: str, panel_backend: str) -> str:
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
        if domain in existing and existing[domain] != backend:
            raise InstallerConflict(f"domain already routed: {domain}")
    marker_count = (block.count(OWNERSHIP_BEGIN), block.count(OWNERSHIP_END))
    managed = (
        f"    {OWNERSHIP_BEGIN}\n"
        f"    {proxy_domain} {proxy_backend};\n"
        f"    {panel_domain} {panel_backend};\n"
        f"    {OWNERSHIP_END}\n"
    )
    if marker_count == (1, 1):
        marker_start = block.index(OWNERSHIP_BEGIN)
        marker_end = block.index(OWNERSHIP_END, marker_start) + len(OWNERSHIP_END)
        current = block[marker_start:marker_end]
        expected = managed.strip()
        if "\n".join(line.strip() for line in current.splitlines()) != "\n".join(line.strip() for line in expected.splitlines()):
            raise InstallerConflict("owned route block differs from requested configuration")
        return text
    if marker_count != (0, 0):
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
    proxy_backend_port: int = 8445
    panel_backend_port: int = 8787

    @classmethod
    def from_audit(cls, report: AuditReport, *, proxy_domain: str, panel_domain: str,
                   proxy_backend_port: int = 8445, panel_backend_port: int = 8787) -> "InstallPlan":
        proxy_domain, panel_domain = validate_domain(proxy_domain), validate_domain(panel_domain)
        known = set(report.nginx.sni_routes) | set(report.nginx.http_domains)
        for domain in (proxy_domain, panel_domain):
            if domain in known:
                raise InstallerConflict(f"domain already routed: {domain}")
        for port in (proxy_backend_port, panel_backend_port):
            if port in report.listening_ports:
                raise InstallerConflict(f"backend port {port} is already listening")
        if not report.nginx.stream_enabled and 443 in report.listening_ports:
            raise InstallerConflict("public 443 is occupied without an Nginx stream router")
        return cls(proxy_domain, panel_domain, proxy_backend_port, panel_backend_port)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxyctl", description="Audit and install Proxy Control safely")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="read-only host audit")
    audit.add_argument("--json", action="store_true")
    plan = sub.add_parser("plan", help="validate domains and produce an installation plan")
    plan.add_argument("--proxy-domain", required=True)
    plan.add_argument("--panel-domain", required=True)
    plan.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = audit_host()
    if args.command == "audit":
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2) if args.json else report)
        return 0
    try:
        plan = InstallPlan.from_audit(report, proxy_domain=args.proxy_domain, panel_domain=args.panel_domain)
    except (InstallerConflict, ValueError) as exc:
        print(f"BLOCKED: {exc}")
        return 2
    print(json.dumps(asdict(plan), indent=2) if args.json else plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
