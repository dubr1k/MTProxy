from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from scripts.proxyctl import InstallerConflict, RuntimeInstaller, RuntimePlan


class FakeRunner:
    """External-command seam; filesystem and transaction behavior remain real."""

    def __init__(
        self,
        *,
        installed: set[str] | None = None,
        fail_on: tuple[str, ...] | None = None,
        fail_once: bool = False,
        failure: type[BaseException] = RuntimeError,
    ):
        self.installed = set(installed or ())
        self.fail_on = fail_on
        self.fail_once = fail_once
        self.failure = failure
        self.calls: list[tuple[tuple[str, ...], str | None]] = []

    def package_installed(self, name: str) -> bool:
        return name in self.installed

    def run(self, argv, *, stdin_path=None, env=None):
        command = tuple(str(value) for value in argv)
        self.calls.append((command, str(stdin_path) if stdin_path else None))
        if self.fail_on and command[: len(self.fail_on)] == self.fail_on:
            if self.fail_once:
                self.fail_on = None
            raise self.failure("injected command failure")
        if command[:3] == ("apt-get", "install", "-y"):
            self.installed.update(command[3:])


def runtime_root(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "root"
    route = root / "etc/nginx/stream.d/routes.conf"
    route.parent.mkdir(parents=True)
    (root / "etc/nginx/sites-available").mkdir(parents=True)
    (root / "etc/nginx/sites-enabled").mkdir(parents=True)
    (root / "etc/nginx/nginx.conf").write_text(
        "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\n"
        "stream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    route.write_text(
        "map $ssl_preread_server_name $upstream_443 {\n"
        "    vpn.example.com 127.0.0.1:10443;\n"
        "    default 127.0.0.1:8443;\n}\n"
        "server { listen 443; ssl_preread on; proxy_pass $upstream_443; }\n"
    )
    return root, route


def plan(repo: Path) -> RuntimePlan:
    return RuntimePlan(
        proxy_domain="tga.dubr1kkk.uk",
        panel_domain="tga-panel.dubr1kkk.uk",
        email="ops@example.com",
        route_file="/etc/nginx/stream.d/routes.conf",
        source_dir=str(repo),
        project_dir="/opt/mtproxy-shared443",
        users=("owner",),
        protocol_probe="/usr/local/bin/mtproxy-respq-probe",
    )


def test_runtime_install_owns_complete_stack_and_never_exposes_password(tmp_path):
    root, route = runtime_root(tmp_path)
    original_route = route.read_text()
    runner = FakeRunner(installed={"python3", "ca-certificates"})
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)

    manifest_path = manager.install()

    state = json.loads(manifest_path.read_text())
    assert state["status"] == "active"
    assert state["owned_packages"] == ["certbot", "curl", "docker-compose-v2", "docker.io", "nginx-full", "openssl"]
    assert state["project_created"] is True
    assert state["managed_files"] == [
        "/etc/nginx/sites-available/proxy-control-acme.conf",
        "/etc/nginx/sites-available/proxy-control-panel.conf",
        "/etc/nginx/sites-enabled/proxy-control-acme.conf",
        "/etc/nginx/sites-enabled/proxy-control-panel.conf",
    ]
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    assert "tga.dubr1kkk.uk 127.0.0.1:8445;" in route.read_text()
    assert "tga-panel.dubr1kkk.uk 127.0.0.1:8443;" in route.read_text()
    assert original_route != route.read_text()

    project = root / "opt/mtproxy-shared443"
    password_file = project / "secrets/panel-bootstrap-password"
    assert password_file.is_file()
    assert stat.S_IMODE(password_file.stat().st_mode) == 0o600
    password = password_file.read_text().strip()
    assert len(password) >= 24
    serialized_calls = json.dumps(runner.calls)
    assert password not in serialized_calls
    bootstrap = next(call for call in runner.calls if "panel.cli" in call[0])
    assert bootstrap[1] == str(password_file)
    assert any(call[0][:2] == ("certbot", "certonly") and "tga-panel.dubr1kkk.uk" in call[0] for call in runner.calls)
    assert any(call[0][0] == "/usr/local/bin/mtproxy-respq-probe" for call in runner.calls)


def test_runtime_uninstall_removes_only_owned_runtime_and_preserves_credentials_by_default(tmp_path):
    root, route = runtime_root(tmp_path)
    original_route = route.read_text()
    runner = FakeRunner()
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)
    manager.install()
    secret = (root / "opt/mtproxy-shared443/secrets/users.conf").read_text()

    manager.uninstall()
    manager.uninstall()

    assert route.read_text() == original_route
    assert not (root / "var/lib/proxy-control/runtime.json").exists()
    assert (root / "opt/mtproxy-shared443/secrets/users.conf").read_text() == secret
    assert not (root / "etc/nginx/sites-available/proxy-control-panel.conf").exists()
    assert any(call[0][-3:] == ("down", "--remove-orphans", "--volumes") for call in runner.calls)
    assert any(call[0][:3] == ("apt-get", "purge", "-y") for call in runner.calls)


def test_runtime_install_failure_rolls_back_routes_sites_compose_and_preserves_credentials(tmp_path):
    root, route = runtime_root(tmp_path)
    original_route = route.read_text()
    runner = FakeRunner(fail_on=("/usr/local/bin/mtproxy-respq-probe",))
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)

    with pytest.raises(RuntimeError, match="injected"):
        manager.install()

    assert route.read_text() == original_route
    assert not (root / "etc/nginx/sites-available/proxy-control-acme.conf").exists()
    assert not (root / "etc/nginx/sites-available/proxy-control-panel.conf").exists()
    project = root / "opt/mtproxy-shared443"
    assert {child.name for child in project.iterdir()} == {".mtproxy-owned", "secrets"}
    assert (project / "secrets/users.conf").is_file()
    state = json.loads((root / "var/lib/proxy-control/runtime.json").read_text())
    assert state["status"] == "installing"
    assert state["phase"] == "rollback_complete"
    assert any(call[0][-3:] == ("down", "--remove-orphans", "--volumes") for call in runner.calls)


def test_runtime_repair_fails_closed_on_managed_site_drift(tmp_path):
    root, _ = runtime_root(tmp_path)
    runner = FakeRunner()
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)
    manager.install()
    site = root / "etc/nginx/sites-available/proxy-control-panel.conf"
    site.write_text(site.read_text() + "# foreign edit\n")

    with pytest.raises(InstallerConflict, match="managed file has drifted"):
        manager.repair()


def test_runtime_refuses_preexisting_project_without_runtime_manifest(tmp_path):
    root, _ = runtime_root(tmp_path)
    project = root / "opt/mtproxy-shared443"
    project.mkdir(parents=True)
    (project / ".mtproxy-owned").write_text("legacy-marker\n")
    existing = project / "compose.yaml"
    existing.write_text("legacy deployment\n")

    with pytest.raises(InstallerConflict, match="pre-existing project"):
        RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=FakeRunner()).install()

    assert existing.read_text() == "legacy deployment\n"


def test_runtime_uninstall_restores_sites_when_route_removal_fails(tmp_path):
    root, route = runtime_root(tmp_path)
    runner = FakeRunner()
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)
    manager.install()
    owned_route = route.read_text()
    panel_site = root / "etc/nginx/sites-available/proxy-control-panel.conf"
    panel_before = panel_site.read_text()
    runner.fail_on = ("nginx", "-t")
    runner.fail_once = True

    with pytest.raises(RuntimeError, match="injected"):
        manager.uninstall()

    assert route.read_text() == owned_route
    assert panel_site.read_text() == panel_before
    assert (root / "etc/nginx/sites-enabled/proxy-control-panel.conf").is_symlink()
    assert (root / "var/lib/proxy-control/runtime.json").is_file()


@pytest.mark.parametrize("crash_command", [
    ("apt-get", "install", "-y"),
    ("certbot", "certonly"),
    ("docker", "compose", "--project-directory", "/opt/mtproxy-shared443", "up"),
    ("/usr/local/bin/mtproxy-respq-probe",),
])
def test_install_resumes_after_crash_at_each_durable_phase_without_rotating_credentials(tmp_path, crash_command):
    root, _ = runtime_root(tmp_path)
    runner = FakeRunner(fail_on=crash_command, fail_once=True, failure=SystemExit)
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)

    with pytest.raises(SystemExit, match="injected"):
        manager.install()
    manifest = root / "var/lib/proxy-control/runtime.json"
    interrupted = json.loads(manifest.read_text())
    assert interrupted["status"] == "installing"
    password = root / "opt/mtproxy-shared443/secrets/panel-bootstrap-password"
    preserved_password = password.read_bytes() if password.exists() else None

    manager.install()

    assert json.loads(manifest.read_text())["status"] == "active"
    if preserved_password is not None:
        assert password.read_bytes() == preserved_password


@pytest.mark.parametrize("crash_command", [
    ("docker", "compose", "--project-directory", "/opt/mtproxy-shared443", "down"),
    ("apt-get", "purge", "-y"),
    ("systemctl", "reload", "nginx"),
])
def test_uninstall_retries_each_destructive_phase_and_preserves_credentials(tmp_path, crash_command):
    root, route = runtime_root(tmp_path)
    original_route = route.read_bytes()
    runner = FakeRunner()
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)
    manager.install()
    secret = (root / "opt/mtproxy-shared443/secrets/users.conf").read_bytes()
    runner.fail_on = crash_command
    runner.fail_once = True
    runner.failure = SystemExit

    with pytest.raises(SystemExit, match="injected"):
        manager.uninstall()
    interrupted = json.loads((root / "var/lib/proxy-control/runtime.json").read_text())
    assert interrupted["status"] == "uninstalling"

    manager.uninstall()

    assert route.read_bytes() == original_route
    assert not (root / "var/lib/proxy-control/runtime.json").exists()
    assert (root / "opt/mtproxy-shared443/secrets/users.conf").read_bytes() == secret


def test_failed_install_rollback_is_retried_before_reinstall(tmp_path):
    root, route = runtime_root(tmp_path)
    original_route = route.read_bytes()
    runner = FakeRunner(fail_on=("/usr/local/bin/mtproxy-respq-probe",))
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)

    with pytest.raises(RuntimeError, match="injected"):
        manager.install()
    state = json.loads((root / "var/lib/proxy-control/runtime.json").read_text())
    assert state["status"] in {"installing", "rollback_failed"}
    runner.fail_on = None

    manager.install()

    assert route.read_bytes() != original_route
    assert json.loads((root / "var/lib/proxy-control/runtime.json").read_text())["status"] == "active"


def test_rollback_failed_state_recovers_but_refuses_foreign_file_drift(tmp_path):
    root, _ = runtime_root(tmp_path)
    runner = FakeRunner(fail_on=("certbot", "certonly"), fail_once=True, failure=SystemExit)
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)
    with pytest.raises(SystemExit):
        manager.install()
    manifest = root / "var/lib/proxy-control/runtime.json"
    state = json.loads(manifest.read_text())
    state["status"] = "rollback_failed"
    state["phase"] = "rollback_sites"
    manifest.write_text(json.dumps(state))
    acme = root / "etc/nginx/sites-available/proxy-control-acme.conf"
    acme.write_text(acme.read_text() + "# foreign edit\n")

    with pytest.raises(InstallerConflict, match="managed file has drifted"):
        manager.install()
    assert acme.exists()
    assert json.loads(manifest.read_text())["status"] == "rollback_failed"

    acme.write_text(acme.read_text().removesuffix("# foreign edit\n"))
    manager.install()
    assert json.loads(manifest.read_text())["status"] == "active"
