from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from version_agent.catalog import CatalogError, load_catalog
from version_agent.service import ConflictError, UpdateError, VersionAgent


TELEMT_IMAGE = "ghcr.io/example/telemt@sha256:" + "a" * 64
BINARY = b"verified-runtime-binary\n"
BINARY_SHA256 = hashlib.sha256(BINARY).hexdigest()


def write_catalog(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "components": {
                    "telemt": [
                        {"version": "3.4.25", "kind": "image", "image": TELEMT_IMAGE}
                    ],
                    "naive": [
                        {
                            "version": "2.11.4-custom.1",
                            "kind": "binary",
                            "url": "https://artifacts.example.com/caddy-2.11.4-custom.1",
                            "sha256": BINARY_SHA256,
                        }
                    ],
                    "mita": [
                        {
                            "version": "3.35.0",
                            "kind": "binary",
                            "url": "https://artifacts.example.com/mita-3.35.0",
                            "sha256": BINARY_SHA256,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )


def test_catalog_requires_immutable_artifacts(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": 1,
                "components": {
                    "telemt": [
                        {"version": "latest", "kind": "image", "image": "ghcr.io/example/telemt:latest"}
                    ],
                    "naive": [],
                    "mita": [],
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CatalogError, match="immutable image"):
        load_catalog(catalog)


def test_catalog_rejects_non_https_binary_sources(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": 1,
                "components": {
                    "telemt": [],
                    "naive": [
                        {
                            "version": "2.11.4",
                            "kind": "binary",
                            "url": "http://artifacts.example.com/caddy",
                            "sha256": "b" * 64,
                        }
                    ],
                    "mita": [],
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CatalogError, match="HTTPS"):
        load_catalog(catalog)


def test_binary_update_uses_catalog_hash_and_persists_revision(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")
    target.chmod(0o755)
    state = tmp_path / "state.json"
    commands: list[tuple[list[str], dict | None]] = []

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append((command, env))
        return "active\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        binary_paths={"naive": target},
        service_names={"naive": "caddy-naive"},
        checkers={"naive": "/usr/local/libexec/check-naive-caddy-build"},
        downloader=lambda url: BINARY,
        runner=run,
    )

    result = agent.update("naive", "2.11.4-custom.1", expected_current=None)

    assert result["version"] == "2.11.4-custom.1"
    assert target.read_bytes() == BINARY
    assert target.stat().st_mode & 0o111
    assert json.loads(state.read_text())["components"]["naive"]["version"] == "2.11.4-custom.1"
    assert any(command == ["systemctl", "reload", "caddy-naive"] for command, _ in commands)
    assert any(env and str(env.get("CADDY_BIN", "")).endswith(".proxy-control-new") for _, env in commands)


def test_binary_update_rolls_back_when_service_reload_fails(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "mita"
    target.write_bytes(b"old")
    target.chmod(0o755)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"components": {"mita": {"version": "3.34.0"}}}))
    calls: list[list[str]] = []
    restart_attempts = 0

    def run(command, *, env=None, cwd=None, timeout=None):
        nonlocal restart_attempts
        calls.append(command)
        if command == ["systemctl", "restart", "mita"]:
            restart_attempts += 1
            if restart_attempts == 1:
                raise RuntimeError("service failed")
        return "active\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        binary_paths={"mita": target},
        service_names={"mita": "mita"},
        downloader=lambda url: BINARY,
        runner=run,
    )

    with pytest.raises(UpdateError, match="rolled back"):
        agent.update("mita", "3.35.0", expected_current="3.34.0")

    assert target.read_bytes() == b"old"
    assert json.loads(state.read_text())["components"]["mita"]["version"] == "3.34.0"
    assert calls.count(["systemctl", "restart", "mita"]) >= 2


def test_update_rejects_stale_expected_revision(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"components": {"naive": {"version": "2.11.3"}}}))

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        binary_paths={"naive": tmp_path / "caddy"},
        downloader=lambda url: BINARY,
        runner=lambda *args, **kwargs: "active\n",
    )

    with pytest.raises(ConflictError, match="changed"):
        agent.update("naive", "2.11.4-custom.1", expected_current="2.11.2")


def test_telemt_update_persists_override_and_uses_expected_compose_files(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"components": {"telemt": {"version": "3.4.24"}}}))
    compose_dir = tmp_path / "deployment"
    compose_dir.mkdir()
    (compose_dir / "compose.yaml").write_text("name: mtproxy\nservices: {}\n", encoding="utf-8")
    commands: list[list[str]] = []

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append(command)
        if command[:2] == ["docker", "inspect"]:
            return "healthy\n"
        return "ok\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        compose_dir=compose_dir,
        compose_files=("compose.yaml",),
        downloader=lambda url: BINARY,
        runner=run,
    )

    result = agent.update("telemt", "3.4.25", expected_current="3.4.24")

    assert result["version"] == "3.4.25"
    override = compose_dir / "version-overrides" / "compose.versions.yaml"
    assert TELEMT_IMAGE in override.read_text(encoding="utf-8")
    assert any("pull" in command for command in commands)
    assert any("up" in command and "mtproxy" in command for command in commands)
    assert any(command[:2] == ["docker", "inspect"] for command in commands)
