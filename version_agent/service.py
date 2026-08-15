from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .catalog import CatalogEntry, CatalogError, load_catalog, sha256_bytes


class UpdateError(RuntimeError):
    """An approved update failed and was rolled back where possible."""


class ConflictError(UpdateError):
    """The runtime changed since the panel read its current revision."""


Runner = Callable[..., str]
Downloader = Callable[[str], bytes]


def _run(command: list[str], *, env=None, cwd=None, timeout=None) -> str:
    merged_env = None
    if env is not None:
        merged_env = os.environ.copy()
        merged_env.update(env)
    result = subprocess.run(
        command,
        cwd=cwd,
        env=merged_env,
        text=True,
        capture_output=True,
        timeout=timeout or 120,
        check=True,
    )
    return result.stdout.strip()


def _download(url: str, *, maximum=256 * 1024 * 1024) -> bytes:
    request = Request(url, headers={"User-Agent": "proxy-control-version-agent/1"})
    with urlopen(request, timeout=120) as response:  # noqa: S310 - catalog validated first
        final = response.geturl()
        source = urlsplit(url)
        destination = urlsplit(final)
        if (
            destination.scheme != "https"
            or destination.hostname != source.hostname
            or destination.port != source.port
        ):
            raise UpdateError("artifact redirect left the catalog host")
        content = bytearray()
        while True:
            chunk = response.read(min(1024 * 1024, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > maximum:
                raise UpdateError("artifact is too large")
        return bytes(content)


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {"schema": 1, "components": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError("version state is unreadable") from exc
    if not isinstance(value, dict) or value.get("schema", 1) != 1 or not isinstance(value.get("components", {}), dict):
        raise UpdateError("version state is invalid")
    return value


class VersionAgent:
    """Apply only artifacts from a root-owned catalog and verify each restart."""

    def __init__(
        self,
        *,
        catalog_path: Path,
        state_path: Path,
        compose_dir: Path | None = None,
        compose_files: tuple[str, ...] = (),
        binary_paths: dict[str, Path] | None = None,
        service_names: dict[str, str] | None = None,
        checkers: dict[str, str] | None = None,
        caddyfiles: dict[str, Path] | None = None,
        telemt_container: str = "proxy-control-mtproxy",
        downloader: Downloader | None = None,
        runner: Runner | None = None,
        health_timeout: float = 60,
    ):
        self.catalog_path = catalog_path
        self.state_path = state_path
        self.compose_dir = compose_dir
        self.compose_files = compose_files
        self.binary_paths = binary_paths or {}
        self.service_names = service_names or {}
        self.checkers = checkers or {}
        self.caddyfiles = caddyfiles or {}
        self.telemt_container = telemt_container
        self.downloader = downloader or _download
        self.runner = runner or _run
        self.health_timeout = health_timeout
        self.lock_path = state_path.with_suffix(state_path.suffix + ".lock")

    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def _state(self) -> dict:
        return _load_state(self.state_path)

    def _save_state(self, state: dict) -> None:
        _atomic_write(self.state_path, json.dumps(state, indent=2, sort_keys=True).encode())

    def list_versions(self) -> dict:
        catalog = load_catalog(self.catalog_path)
        state = self._state()
        components = {}
        for component, entries in catalog.components.items():
            current = state.get("components", {}).get(component, {})
            components[component] = {
                "current": current.get("version") if isinstance(current, dict) else None,
                "available": [entry.public() for entry in entries],
            }
        return {"enabled": True, "components": components}

    def update(self, component: str, version: str, expected_current: str | None = None) -> dict:
        if component not in {"telemt", "naive", "mita"}:
            raise CatalogError("unsupported component")
        with self._locked():
            catalog = load_catalog(self.catalog_path)
            entry = catalog.entry(component, version)
            state = self._state()
            current_data = state.setdefault("components", {}).get(component, {})
            current = current_data.get("version") if isinstance(current_data, dict) else None
            if expected_current is not None and current != expected_current:
                raise ConflictError("runtime version changed; reload the versions page")
            if current == version:
                return {"component": component, "version": version, "changed": False}
            try:
                if component == "telemt":
                    self._update_telemt(entry)
                else:
                    self._update_binary(component, entry)
            except ConflictError:
                raise
            except Exception as exc:
                if isinstance(exc, UpdateError):
                    raise
                raise UpdateError(f"{component} update failed and was rolled back") from exc
            state["components"][component] = {
                "version": version,
                "kind": entry.kind,
                "image": entry.image,
                "url": entry.url,
                "sha256": entry.sha256,
                "runtime_version": entry.runtime_version,
                "updated_at": int(time.time()),
            }
            self._save_state(state)
            return {"component": component, "version": version, "changed": True}

    def _update_binary(self, component: str, entry: CatalogEntry) -> None:
        if entry.kind != "binary" or not entry.url or not entry.sha256:
            raise UpdateError("binary catalog entry is incomplete")
        target = self.binary_paths.get(component)
        service = self.service_names.get(component)
        if target is None or service is None:
            raise UpdateError(f"{component} runtime is not configured")
        if target.is_symlink():
            raise UpdateError(f"refusing to replace symlink {target}")
        payload = self.downloader(entry.url)
        if sha256_bytes(payload) != entry.sha256:
            raise UpdateError(f"{component} artifact SHA-256 mismatch")
        target.parent.mkdir(parents=True, exist_ok=True)
        backup_dir = self.state_path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / f"{component}.previous"
        existed = target.exists()
        if existed:
            shutil.copyfile(target, backup)
            os.chmod(backup, target.stat().st_mode & 0o777)
        stage = target.with_name(f".{target.name}.proxy-control-new")
        try:
            _atomic_write(stage, payload, 0o755)
            checker = self.checkers.get(component)
            if checker:
                checker_env = {"CADDY_BIN": str(stage)}
                if entry.runtime_version:
                    checker_env["EXPECTED_CADDY_VERSION"] = entry.runtime_version
                self.runner([str(checker)], env=checker_env)
            os.replace(stage, target)
            self._fsync_directory(target.parent)
            if component == "naive":
                caddyfile = self.caddyfiles.get(component)
                if caddyfile:
                    self.runner(
                        [str(target), "adapt", "--adapter", "caddyfile", "--validate", "--config", str(caddyfile)]
                    )
                action = "reload"
            else:
                action = "restart"
            self.runner(["systemctl", action, service], timeout=120)
            self.runner(["systemctl", "is-active", service], timeout=30)
        except Exception as exc:
            try:
                if existed:
                    os.replace(backup, target)
                else:
                    target.unlink(missing_ok=True)
                self._fsync_directory(target.parent)
                self.runner(["systemctl", "restart" if component == "mita" else "reload", service], timeout=120)
            except Exception as rollback_exc:
                raise UpdateError(f"{component} update failed; rollback also failed") from rollback_exc
            raise UpdateError(f"{component} update failed and was rolled back") from exc
        finally:
            stage.unlink(missing_ok=True)

    def _compose_command(self, *args: str, include_override: bool = True) -> list[str]:
        if self.compose_dir is None or not self.compose_files:
            raise UpdateError("Telemt Compose deployment is not configured")
        command = ["docker", "compose", "--project-name", "mtproxy"]
        for compose_file in self.compose_files:
            path = Path(compose_file)
            if path.is_absolute() or ".." in path.parts:
                raise UpdateError("invalid Compose file path")
            command.extend(["-f", str(self.compose_dir / path)])
        if include_override:
            command.extend(["-f", str(self.compose_dir / "version-overrides" / "compose.versions.yaml")])
        command.extend(args)
        return command

    def _update_telemt(self, entry: CatalogEntry) -> None:
        if entry.kind != "image" or not entry.image:
            raise UpdateError("Telemt catalog entry is incomplete")
        override = self.compose_dir / "version-overrides" / "compose.versions.yaml" if self.compose_dir else None
        if override is None:
            raise UpdateError("Telemt Compose deployment is not configured")
        previous = override.read_bytes() if override.exists() else None
        content = (
            "# Generated by proxy-control version-agent; do not edit manually.\n"
            "services:\n"
            "  mtproxy:\n"
            f"    image: {entry.image}\n"
        ).encode()
        _atomic_write(override, content, 0o640)
        try:
            self.runner(self._compose_command("pull", "mtproxy"), cwd=self.compose_dir, timeout=900)
            self.runner(
                self._compose_command("up", "-d", "--no-deps", "mtproxy"),
                cwd=self.compose_dir,
                timeout=300,
            )
            deadline = time.monotonic() + self.health_timeout
            status = ""
            while time.monotonic() < deadline:
                status = self.runner(
                    ["docker", "inspect", "--format", "{{.State.Health.Status}}", self.telemt_container],
                    timeout=30,
                ).strip()
                if status == "healthy":
                    return
                time.sleep(1)
            raise UpdateError(f"Telemt health did not become healthy: {status or 'unknown'}")
        except Exception as exc:
            try:
                if previous is None:
                    override.unlink(missing_ok=True)
                    command = self._compose_command("up", "-d", "--no-deps", "mtproxy", include_override=False)
                else:
                    _atomic_write(override, previous, 0o640)
                    command = self._compose_command("up", "-d", "--no-deps", "mtproxy")
                self.runner(command, cwd=self.compose_dir, timeout=300)
            except Exception as rollback_exc:
                raise UpdateError("Telemt update failed; rollback also failed") from rollback_exc
            if isinstance(exc, UpdateError):
                raise UpdateError(f"{exc}; rolled back") from exc
            raise UpdateError("Telemt update failed and was rolled back") from exc

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def agent_from_env() -> VersionAgent:
    def paths(prefix: str, default: str) -> dict[str, Path]:
        value = os.getenv(prefix, default)
        return {key: Path(item) for key, item in (part.split("=", 1) for part in value.split(",") if "=" in part)}

    compose_files = tuple(filter(None, os.getenv("PROXY_CONTROL_COMPOSE_FILES", "compose.yaml").split(":")))
    return VersionAgent(
        catalog_path=Path(os.getenv("PROXY_CONTROL_VERSION_CATALOG", "/etc/proxy-control/versions.json")),
        state_path=Path(os.getenv("PROXY_CONTROL_VERSION_STATE", "/var/lib/proxy-control/version-agent/state.json")),
        compose_dir=Path(os.getenv("PROXY_CONTROL_COMPOSE_DIR", "/opt/mtproxy-shared443")),
        compose_files=compose_files,
        binary_paths=paths("PROXY_CONTROL_BINARY_PATHS", "naive=/usr/local/bin/caddy,mita=/usr/bin/mita"),
        service_names={key: value for key, value in (part.split("=", 1) for part in os.getenv("PROXY_CONTROL_SERVICE_NAMES", "naive=caddy-naive,mita=mita").split(",") if "=" in part)},
        checkers=paths("PROXY_CONTROL_CHECKERS", "naive=/usr/local/libexec/check-naive-caddy-build"),
        caddyfiles=paths("PROXY_CONTROL_CADDYFILES", "naive=/var/lib/naive-manager/Caddyfile"),
        telemt_container=os.getenv("PROXY_CONTROL_TELEMT_CONTAINER", "proxy-control-mtproxy"),
        health_timeout=float(os.getenv("PROXY_CONTROL_VERSION_HEALTH_TIMEOUT", "60")),
    )
