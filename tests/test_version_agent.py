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
PINNED_CADDY = "v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0="


def write_catalog(path: Path, *, naive_runtime_version: str | None = None) -> None:
    naive = {
        "version": "2.11.4-custom.1",
        "kind": "binary",
        "url": "https://artifacts.example.com/caddy-2.11.4-custom.1",
        "sha256": BINARY_SHA256,
    }
    if naive_runtime_version:
        naive["runtime_version"] = naive_runtime_version
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "components": {
                    "telemt": [
                        {"version": "3.4.25", "kind": "image", "image": TELEMT_IMAGE}
                    ],
                    "naive": [naive],
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
    # A reload keeps the running process on the old binary, so replacing it restarts.
    assert any(command == ["systemctl", "restart", "caddy-naive"] for command, _ in commands)
    assert not any(command[:2] == ["systemctl", "reload"] for command, _ in commands)
    assert any(env and str(env.get("CADDY_BIN", "")).endswith(".proxy-control-new") for _, env in commands)


def test_binary_update_records_the_pin_the_unit_check_reads(tmp_path: Path):
    """ExecStartPre runs without the agent's environment: the pin must persist."""
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, naive_runtime_version=PINNED_CADDY)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")
    target.chmod(0o755)
    pin = tmp_path / "caddy-naive.pin"
    pin.write_text("v2.11.3 h1:stale=\n")

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=tmp_path / "state.json",
        binary_paths={"naive": target},
        service_names={"naive": "caddy-naive"},
        version_pins={"naive": pin},
        downloader=lambda url: BINARY,
        runner=lambda command, *, env=None, cwd=None, timeout=None: "active\n",
    )

    agent.update("naive", "2.11.4-custom.1", expected_current=None)

    assert pin.read_text().strip() == PINNED_CADDY


def test_binary_update_restores_the_previous_pin_when_the_service_fails(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, naive_runtime_version=PINNED_CADDY)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")
    target.chmod(0o755)
    pin = tmp_path / "caddy-naive.pin"
    pin.write_text("v2.11.3 h1:previous=\n")

    def run(command, *, env=None, cwd=None, timeout=None):
        if command[:2] == ["systemctl", "restart"] and target.read_bytes() == BINARY:
            raise RuntimeError("restart failed")
        return "active\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=tmp_path / "state.json",
        binary_paths={"naive": target},
        service_names={"naive": "caddy-naive"},
        version_pins={"naive": pin},
        downloader=lambda url: BINARY,
        runner=run,
    )

    with pytest.raises(UpdateError, match="rolled back"):
        agent.update("naive", "2.11.4-custom.1", expected_current=None)

    assert target.read_bytes() == b"old"
    assert pin.read_text().strip() == "v2.11.3 h1:previous="


def test_update_is_refused_while_a_container_pins_the_binary(tmp_path: Path):
    """A digest-pinned consumer would keep the old inode and a stale hash."""
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "mita"
    target.write_bytes(b"old")
    target.chmod(0o755)
    downloads: list[str] = []

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=tmp_path / "state.json",
        binary_paths={"mita": target},
        service_names={"mita": "mita"},
        pinned_consumers={"mita": "proxy-control-mieru-manager"},
        downloader=lambda url: downloads.append(url) or BINARY,
        runner=lambda command, *, env=None, cwd=None, timeout=None: "container-id\n",
    )

    with pytest.raises(UpdateError, match="proxy-control-mieru-manager"):
        agent.update("mita", "3.35.0", expected_current=None)

    assert target.read_bytes() == b"old"
    assert downloads == []


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
        telemt_container="telemt-test",
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
    inspect_commands = [command for command in commands if command[:2] == ["docker", "inspect"]]
    assert inspect_commands and inspect_commands[-1][-1] == "telemt-test"
