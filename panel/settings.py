from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _secret_setting(name: str, file_name: str) -> str:
    if os.getenv(file_name):
        return Path(os.environ[file_name]).read_text().strip()
    return os.getenv(name, "")


@dataclass(frozen=True)
class Settings:
    database_path: Path = Path(os.getenv("PANEL_DATABASE", "/data/panel.sqlite3"))
    telemt_url: str = os.getenv("TELEMT_API_URL", "http://mtproxy:9091")
    telemt_token: str = field(
        default_factory=lambda: _secret_setting(
            "TELEMT_API_TOKEN", "TELEMT_API_TOKEN_FILE"
        )
    )
    naive_socket: str = os.getenv(
        "NAIVE_MANAGER_SOCKET", "/run/naive-manager/manager.sock"
    )
    naive_token: str = field(
        default_factory=lambda: _secret_setting(
            "NAIVE_MANAGER_TOKEN", "NAIVE_MANAGER_TOKEN_FILE"
        )
    )
    naive_public_host: str = os.getenv("NAIVE_PUBLIC_HOST", "")
    naive_enabled: bool = os.getenv("NAIVE_ENABLED", "false").lower() == "true"
    mieru_socket: str = os.getenv(
        "MIERU_MANAGER_SOCKET", "/run/mieru-manager/manager.sock"
    )
    mieru_token: str = field(
        default_factory=lambda: _secret_setting(
            "MIERU_MANAGER_TOKEN", "MIERU_MANAGER_TOKEN_FILE"
        )
    )
    mieru_enabled: bool = os.getenv("MIERU_ENABLED", "false").lower() == "true"
    version_agent_socket: str = os.getenv(
        "VERSION_AGENT_SOCKET", "/run/proxy-control/version-agent.sock"
    )
    session_cookie_secure: bool = (
        os.getenv("PANEL_COOKIE_SECURE", "true").lower() == "true"
    )
    allowed_hosts: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            filter(
                None, os.getenv("PANEL_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
            )
        )
    )
    session_ttl_seconds: int = 12 * 3600
    login_attempts: int = 5
    login_window_seconds: int = 300
    reveal_ttl_seconds: int = 120
    body_limit_bytes: int = 65536
    login_verify_concurrency: int = 2
