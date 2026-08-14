from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.proxyctl import CommandRunner, InstallerConflict, RuntimeInstaller, RuntimePlan

proxyctl = sys.modules[RuntimeInstaller.__module__]


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

    def capture(self, argv, *, max_chars) -> str:
        command = tuple(str(value) for value in argv)
        self.calls.append((command, None))
        if command[-1:] == ("ps",):
            return "panel running (unhealthy)"
        if command[-5:] == ("logs", "--no-color", "--tail", "80", "panel"):
            return "panel log password=do-not-expose"
        if command[-3:] == ("ps", "-q", "panel"):
            return "panel-container-id"
        if command[:2] == ("docker", "inspect"):
            return '{"Status":"unhealthy","Log":[{"Output":"Bearer do-not-expose"}]}'
        return ""


def test_command_runner_reports_captured_stderr_for_failed_command():
    with pytest.raises(InstallerConflict, match="specific compose failure"):
        CommandRunner().run(("sh", "-c", "printf 'specific compose failure\\n' >&2; exit 7"))


def test_compose_start_failure_reports_bounded_sanitized_diagnostics_and_rolls_back(tmp_path):
    root, route = runtime_root(tmp_path)
    original_route = route.read_bytes()
    runner = FakeRunner(
        fail_on=("docker", "compose", "--project-directory", "/opt/mtproxy-shared443", "up"),
        failure=InstallerConflict,
    )
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)

    with pytest.raises(InstallerConflict) as caught:
        manager.install()

    message = str(caught.value)
    assert "injected command failure" in message
    assert "panel running (unhealthy)" in message
    assert "panel log password=[REDACTED]" in message
    assert '"Status":"unhealthy"' in message
    assert "do-not-expose" not in message
    commands = [call[0] for call in runner.calls]
    compose = ("docker", "compose", "--project-directory", "/opt/mtproxy-shared443")
    assert compose + ("ps",) in commands
    assert compose + ("logs", "--no-color", "--tail", "80", "panel") in commands
    assert compose + ("ps", "-q", "panel") in commands
    assert ("docker", "inspect", "--format", "{{json .State.Health}}", "panel-container-id") in commands
    assert all("Config" not in command and "Env" not in command for command in commands)
    assert route.read_bytes() == original_route
    assert {child.name for child in (root / "opt/mtproxy-shared443").iterdir()} == {".mtproxy-owned", "secrets"}


def test_compose_start_keeps_health_diagnostics_ahead_of_bounded_logs_and_ps():
    class VerboseRunner(FakeRunner):
        def run(self, argv, *, stdin_path=None, env=None):
            command = tuple(str(value) for value in argv)
            self.calls.append((command, str(stdin_path) if stdin_path else None))
            raise InstallerConflict("compose progress " + "P" * 5000 + " container panel is unhealthy")

        def capture(self, argv, *, max_chars) -> str:
            command = tuple(str(value) for value in argv)
            self.calls.append((command, None))
            if command[-3:] == ("ps", "-q", "panel"):
                return "panel-container-id"
            if command[:2] == ("docker", "inspect"):
                return '{"Status":"unhealthy","Log":[{"Output":"health-marker token=hidden"}]}'
            if command[-5:] == ("logs", "--no-color", "--tail", "80", "panel"):
                return "log-marker " + "L" * 5000
            if command[-1:] == ("ps",):
                return "ps-marker " + "S" * 5000
            return ""

    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), runner=VerboseRunner())

    with pytest.raises(InstallerConflict) as caught:
        manager._compose_start()

    message = str(caught.value)
    assert len(message) <= 3900
    assert "health-marker token=[REDACTED]" in message
    assert "hidden" not in message
    assert message.index("panel health:") < message.index("panel logs:") < message.index("compose ps:")
    assert message.index("health-marker") < 4000


def test_test_hook_kills_process_only_after_requested_phase_is_durable(tmp_path):
    root = tmp_path / "root"
    code = """
from pathlib import Path
from scripts.proxyctl import RuntimeInstaller, RuntimePlan
plan = RuntimePlan(proxy_domain='proxy.example.com', panel_domain='panel.example.com',
    email='lab@example.com', route_file='/etc/nginx/stream.d/routes.conf',
    source_dir='.', protocol_probe='/bin/true')
manager = RuntimeInstaller(plan, root=Path(r'%s'))
manager._checkpoint({}, status='installing', phase='project_rendered')
""" % root
    completed = subprocess.run(
        [sys.executable, "-c", code], cwd=Path(__file__).parents[1],
        env={**os.environ, "PROXYCTL_TEST_CRASH_AFTER_PHASE": "project_rendered"},
    )
    assert completed.returncode == -signal.SIGKILL
    state = json.loads((root / "var/lib/proxy-control/runtime.json").read_text())
    assert state == {"phase": "project_rendered", "status": "installing"}


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
        proxy_domain="proxy.example.com",
        panel_domain="panel.example.com",
        email="ops@example.com",
        route_file="/etc/nginx/stream.d/routes.conf",
        source_dir=str(repo),
        project_dir="/opt/mtproxy-shared443",
        users=("owner",),
        protocol_probe="/usr/local/bin/mtproxy-respq-probe",
    )


def test_generated_acme_and_panel_sites_pass_native_nginx_syntax_check(tmp_path):
    nginx = shutil.which("nginx")
    assert nginx is not None, "native nginx is required for generated-site syntax validation"
    runtime_plan = plan(Path(__file__).parents[1])
    manager = RuntimeInstaller(runtime_plan, root=tmp_path, runner=FakeRunner())
    acme_site = manager._acme_site_content()
    panel_site = manager._panel_site_content()

    certificate = tmp_path / "fullchain.pem"
    private_key = tmp_path / "privkey.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN={runtime_plan.panel_domain}", "-days", "1",
            "-keyout", str(private_key), "-out", str(certificate),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    panel_site = panel_site.replace(
        f"/etc/letsencrypt/live/{runtime_plan.proxy_domain}/fullchain.pem".encode(),
        str(certificate).encode(),
    ).replace(
        f"/etc/letsencrypt/live/{runtime_plan.proxy_domain}/privkey.pem".encode(),
        str(private_key).encode(),
    )
    (tmp_path / "nginx.conf").write_bytes(
        b"worker_processes 1; pid nginx.pid; error_log stderr notice; events {} http {\n"
        + acme_site
        + panel_site
        + b"}\n"
    )

    checked = subprocess.run(
        [nginx, "-t", "-p", f"{tmp_path}/", "-c", "nginx.conf"],
        capture_output=True,
        text=True,
    )
    assert checked.returncode == 0, checked.stderr
    assert acme_site.count(b"{") == acme_site.count(b"}") == 6
    assert panel_site.count(b"{") == panel_site.count(b"}") == 2


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
    assert "proxy.example.com 127.0.0.1:8445;" in route.read_text()
    assert "panel.example.com 127.0.0.1:8443;" in route.read_text()
    assert original_route != route.read_text()

    project = root / "opt/mtproxy-shared443"
    rendered_env = (project / ".env").read_text().splitlines()
    assert "PANEL_ALLOWED_HOSTS=panel.example.com" in rendered_env
    assert "PANEL_HEALTHCHECK_HOST=panel.example.com" in rendered_env
    password_file = project / "secrets/panel-bootstrap-password"
    assert password_file.is_file()
    assert stat.S_IMODE(password_file.stat().st_mode) == 0o600
    password = password_file.read_text().strip()
    assert len(password) >= 24
    serialized_calls = json.dumps(runner.calls)
    assert password not in serialized_calls
    bootstrap = next(call for call in runner.calls if "panel.cli" in call[0])
    assert bootstrap[1] == str(password_file)
    assert any(call[0][:2] == ("certbot", "certonly") and "panel.example.com" in call[0] for call in runner.calls)
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


def test_uninstall_resumes_when_crash_hits_nested_ownership_uninstall_checkpoint(tmp_path, monkeypatch):
    """A durable inner `uninstalling` journal must be resumable by the outer transaction."""
    root, route = runtime_root(tmp_path)
    original_route = route.read_bytes()
    runner = FakeRunner()
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=runner)
    manager.install()
    real_write_state = proxyctl._write_state
    crashed = False

    def crash_after_nested_checkpoint(path, state):
        nonlocal crashed
        real_write_state(path, state)
        if path.name == "ownership.json" and state["status"] == "uninstalling" and not crashed:
            crashed = True
            raise SystemExit("injected nested checkpoint crash")

    monkeypatch.setattr(proxyctl, "_write_state", crash_after_nested_checkpoint)
    with pytest.raises(SystemExit, match="nested checkpoint"):
        manager.uninstall()

    runtime_state = json.loads((root / "var/lib/proxy-control/runtime.json").read_text())
    ownership_state = json.loads((root / "var/lib/proxy-control/ownership.json").read_text())
    assert runtime_state["phase"] == "compose_down"
    assert ownership_state["status"] == "uninstalling"

    manager.uninstall()

    assert route.read_bytes() == original_route
    assert not (root / "var/lib/proxy-control/runtime.json").exists()
    assert not (root / "var/lib/proxy-control/ownership.json").exists()


def test_runtime_phase_checkpoints_follow_durable_filesystem_mutations(tmp_path, monkeypatch):
    """Copied trees, symlinks, mkdirs, and removals must reach disk before their phase journals."""
    root, _ = runtime_root(tmp_path)
    manager = RuntimeInstaller(plan(Path(__file__).parents[1]), root=root, runner=FakeRunner())
    real_fsync = os.fsync
    synced: set[Path] = set()
    phase_syncs: dict[str, set[Path]] = {}

    def track_fsync(fd):
        try:
            synced.add(Path(os.readlink(f"/proc/self/fd/{fd}")))
        except OSError:
            pass
        return real_fsync(fd)

    real_checkpoint = manager._checkpoint

    def capture_checkpoint(state, *, status=None, phase=None):
        real_checkpoint(state, status=status, phase=phase)
        if phase is not None:
            phase_syncs[phase] = set(synced)
        if phase in {"sites_removing", "sites_removed"}:
            synced.clear()

    monkeypatch.setattr(proxyctl.os, "fsync", track_fsync)
    monkeypatch.setattr(manager, "_checkpoint", capture_checkpoint)

    manager.install()

    project = root / "opt/mtproxy-shared443"
    assert project / "compose.yaml" in phase_syncs["project_rendered"]
    assert project / "scripts/proxyctl.py" in phase_syncs["project_rendered"]
    assert project / "docker" in phase_syncs["project_rendered"]
    assert project / "panel" in phase_syncs["project_rendered"]
    assert root / "var/www/proxy.example.com/.well-known/acme-challenge" in phase_syncs["sites_installed"]
    assert root / "etc/nginx/sites-enabled" in phase_syncs["sites_installed"]

    manager.uninstall()

    assert root / "etc/nginx/sites-available" in phase_syncs["sites_removed"]
    assert root / "etc/nginx/sites-enabled" in phase_syncs["sites_removed"]
    assert project in phase_syncs["project_cleaned"]


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
