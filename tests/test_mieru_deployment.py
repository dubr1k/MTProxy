from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[1]
STATE_PREPARER = ROOT / "scripts" / "prepare-mieru-state.sh"
TOKEN_PREPARER = ROOT / "scripts" / "prepare-mieru-token.sh"
TOKEN_PREPARER_HELPER = ROOT / "scripts" / "prepare_mieru_token.py"
MITA_AMD64_PACKAGE_SHA256 = "cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342"
MITA_ARM64_PACKAGE_SHA256 = "66ff435dd5bd6078944cb4eb7fc427366afaac5ab51030ff62561c645c31a9e3"
MITA_AMD64_EXECUTABLE_SHA256 = "4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31"
MITA_ARM64_EXECUTABLE_SHA256 = "a4e486c1531b7bebec02eca2b60dcba2a4971b2cd479c590d8405aab59fe6a23"


def run_state_preparer(mode: str, state_dir: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(STATE_PREPARER), mode, str(state_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def run_token_preparer(mode: str, token_file: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(TOKEN_PREPARER), mode, str(token_file)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.fixture
def trusted_token_dir() -> Path:
    path = Path(tempfile.mkdtemp(prefix="mtproxy-token-test-", dir="/var/lib"))
    path.chmod(0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path)


def render_mieru_compose() -> dict:
    env = {
        **os.environ,
        "MIERU_PUBLIC_HOST": "mieru.example.com",
        "MIERU_MITA_BIN": "/opt/pinned/mita",
        "MIERU_MITA_SHA256": MITA_AMD64_EXECUTABLE_SHA256,
        "MIERU_MITA_GID": "321",
        "MIERU_MANAGER_TOKEN_FILE": "/etc/mieru-manager/token",
        "MTPROXY_DOMAIN": "mt.example.com",
        "MTPROXY_BACKEND_PORT": "8445",
        "MTPROXY_COVER_ROOT": "/tmp",
    }
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "compose.yaml",
            "-f",
            "compose.mieru.yaml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_mieru_overlay_supplies_pinned_host_binary_and_read_only_uds_access():
    config = render_mieru_compose()
    manager = config["services"]["mieru-manager"]
    mounts = {item["target"]: item for item in manager["volumes"]}

    assert mounts["/usr/bin/mita"] == {
        "type": "bind",
        "source": "/opt/pinned/mita",
        "target": "/usr/bin/mita",
        "read_only": True,
        "bind": {"create_host_path": False},
    }
    assert mounts["/run/mita"]["read_only"] is True
    assert mounts["/run/mita"]["source"] == "/run/mita"
    assert mounts["/run/mita"]["bind"] == {"create_host_path": False}
    assert mounts["/var/lib/mieru-manager"]["bind"] == {"create_host_path": False}
    assert manager["group_add"] == ["321"]
    assert manager["user"] == "10005:10005"
    assert manager["environment"]["MIERU_MITA_SHA256"] == MITA_AMD64_EXECUTABLE_SHA256
    assert manager["read_only"] is True
    assert manager["environment"]["TMPDIR"] == "/run/mieru-manager"
    assert manager["cap_drop"] == ["ALL"]
    assert manager["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-m",
        "mieru_manager.healthcheck",
    ]
    panel = config["services"]["panel"]
    assert panel["depends_on"]["mieru-manager"]["condition"] == "service_healthy"
    assert panel["group_add"] == ["10005"]
    assert panel["environment"]["PANEL_SUPPLEMENTARY_GROUPS"] == "10005"
    assert panel["environment"]["MIERU_MANAGER_TOKEN_SOURCE"] == "/run/secrets/mieru-manager-token"
    assert "MIERU_MANAGER_TOKEN_FILE" not in panel["environment"]
    assert config["secrets"]["mieru-manager-token"]["file"] == "/etc/mieru-manager/token"


def test_mieru_overlay_has_only_intended_writable_runtime_mounts():
    manager = render_mieru_compose()["services"]["mieru-manager"]
    writable_targets = {
        item["target"] for item in manager["volumes"] if not item.get("read_only", False)
    }
    assert writable_targets == {"/var/lib/mieru-manager", "/run/mieru-manager"}
    assert manager["tmpfs"] == ["/tmp:size=8m,mode=0700"]
    assert manager["pids_limit"] == 128


def test_mita_systemd_unit_keeps_socket_directory_stable_and_config_mutable():
    unit = (ROOT / "deploy" / "mita.service").read_text()
    tmpfiles = (ROOT / "deploy" / "mita.tmpfiles.conf").read_text()
    assert "RuntimeDirectory=mita" not in unit
    assert "MITA_CONFIG_JSON_FILE=/var/lib/mita/server_config.json" in unit
    assert "ExecStartPost=" in unit and "/usr/bin/mita start" in unit
    assert "d /run/mita 0770 mita mita -" in tmpfiles


def test_systemd_manager_uses_reserved_mieru_identity():
    unit = (ROOT / "deploy" / "mieru-manager.service").read_text()
    assert "User=10005" in unit
    assert "Group=10005" in unit


@pytest.mark.skipif(os.geteuid() != 0, reason="numeric permission behavior requires root")
def test_naive_caddy_identity_cannot_access_mieru_state(tmp_path):
    tmp_path.chmod(0o755)
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 10005, 10005)
    secret = state_dir / "state.json"
    secret.write_bytes(b"opaque")
    secret.chmod(0o600)
    os.chown(secret, 10005, 10005)

    read_probe = subprocess.run(
        ["setpriv", "--reuid=10003", "--regid=10004", "--clear-groups", "test", "-r", str(secret)],
        check=False,
    )
    write_probe = subprocess.run(
        ["setpriv", "--reuid=10003", "--regid=10004", "--clear-groups", "test", "-w", str(secret)],
        check=False,
    )
    assert read_probe.returncode != 0
    assert write_probe.returncode != 0


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_prepare_fresh_state_allows_fixed_container_identity_to_write(tmp_path):
    state_dir = tmp_path / "state"
    assert STATE_PREPARER.exists(), "state preparation command is required"

    prepared = run_state_preparer("prepare", state_dir)

    assert prepared.returncode == 0, prepared.stderr
    info = state_dir.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777) == (10005, 10005, 0o700)
    probe = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "10005:10005",
            "--mount",
            f"type=bind,src={state_dir},dst=/state",
            "--entrypoint",
            "python",
            "mtproxy-mieru-manager:latest",
            "-c",
            "from pathlib import Path; Path('/state/probe').touch()",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr
    assert (state_dir / "probe").stat().st_uid == 10005


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_rejects_root_owned_state_directory(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode != 0
    assert "owner 10005:10005" in verified.stderr
    assert state_dir.stat().st_uid == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_prepare_refuses_symlink_in_state_path(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    prepared = run_state_preparer("prepare", linked_parent / "state")

    assert prepared.returncode != 0
    assert "symlink" in prepared.stderr
    assert not (real_parent / "state").exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_rejects_restored_active_journal_without_key(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 10005, 10005)
    journal = state_dir / "journal.json"
    journal.write_text("restored journal must remain opaque to verifier")
    journal.chmod(0o600)
    os.chown(journal, 10005, 10005)

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode != 0
    assert "journal.key" in verified.stderr
    assert "co-restore" in verified.stderr


def owned_private_file(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)
    os.chown(path, 10005, 10005)


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_accepts_complete_restore_without_changing_recovery_files(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 10005, 10005)
    restored = {
        "state.json": b"opaque state",
        "writer.lock": b"",
        "journal.key": b"k" * 32,
        "journal.json": b"opaque active journal",
    }
    for name, content in restored.items():
        owned_private_file(state_dir / name, content)
    backups = state_dir / "backups"
    backups.mkdir(mode=0o700)
    os.chown(backups, 10005, 10005)
    owned_private_file(backups / "g0-restored.json", b"opaque backup")

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode == 0, verified.stderr
    assert "opaque" not in verified.stdout + verified.stderr
    for name, content in restored.items():
        assert (state_dir / name).read_bytes() == content
    assert (backups / "g0-restored.json").read_bytes() == b"opaque backup"


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_rejects_root_owned_recovery_file_without_repairing_it(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 10005, 10005)
    state_file = state_dir / "state.json"
    state_file.write_bytes(b"restored")
    state_file.chmod(0o600)

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode != 0
    assert "state.json must have owner 10005:10005" in verified.stderr
    assert state_file.stat().st_uid == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_rejects_symlinked_recovery_file(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 10005, 10005)
    target = tmp_path / "key"
    owned_private_file(target, b"k" * 32)
    (state_dir / "journal.key").symlink_to(target)

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode != 0
    assert "journal.key must not be a symlink" in verified.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_rejects_wrong_length_journal_key(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 10005, 10005)
    owned_private_file(state_dir / "journal.key", b"short")

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode != 0
    assert "exactly 32 bytes" in verified.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_prepare_refuses_nonempty_directory_without_altering_it(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o755)
    marker = state_dir / "existing"
    marker.write_text("leave me")

    prepared = run_state_preparer("prepare", state_dir)

    assert prepared.returncode != 0
    assert "use verify" in prepared.stderr
    assert marker.read_text() == "leave me"
    assert (state_dir.stat().st_uid, state_dir.stat().st_mode & 0o777) == (0, 0o755)


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_prepare_refuses_non_normalized_path(tmp_path):
    unsafe_path = f"{tmp_path}/future/../state"

    prepared = run_state_preparer("prepare", unsafe_path)

    assert prepared.returncode != 0
    assert "normalized" in prepared.stderr
    assert not (tmp_path / "state").exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_refuses_non_directory_state_path(tmp_path):
    state_file = tmp_path / "state"
    state_file.touch()

    verified = run_state_preparer("verify", state_file)

    assert verified.returncode != 0
    assert "real directory" in verified.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
def test_prepare_token_changes_only_metadata_and_manager_identity_can_read(trusted_token_dir):
    token = trusted_token_dir / "mieru-token"
    content = b"opaque-token-material-that-is-long-enough\n"
    token.write_bytes(content)
    token.chmod(0o600)

    prepared = run_token_preparer("prepare", token)

    assert prepared.returncode == 0, prepared.stderr
    assert token.read_bytes() == content
    info = token.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777) == (0, 10005, 0o440)
    trusted_token_dir.chmod(0o711)
    probe = subprocess.run(
        ["setpriv", "--reuid=10005", "--regid=10005", "--clear-groups", "test", "-r", str(token)],
        check=False,
    )
    assert probe.returncode == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
def test_verify_token_is_nonmutating_for_restored_metadata(trusted_token_dir):
    token = trusted_token_dir / "mieru-token"
    token.write_bytes(b"x" * 32)
    token.chmod(0o400)
    before = token.stat()

    verified = run_token_preparer("verify", token)

    after = token.stat()
    assert verified.returncode != 0
    assert (after.st_uid, after.st_gid, after.st_mode) == (before.st_uid, before.st_gid, before.st_mode)


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
@pytest.mark.parametrize("unsafe", ["relative-token", "/tmp/../tmp/token", "/"])
def test_token_preparer_refuses_unsafe_paths_without_creating_them(unsafe):
    result = run_token_preparer("prepare", unsafe)
    assert result.returncode != 0


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
def test_token_preparer_refuses_symlink_and_wrong_size(trusted_token_dir):
    target = trusted_token_dir / "target"
    target.write_bytes(b"x" * 32)
    link = trusted_token_dir / "token"
    link.symlink_to(target)
    assert run_token_preparer("prepare", link).returncode != 0
    assert (target.stat().st_uid, target.stat().st_gid, target.stat().st_mode & 0o777) == (0, 0, 0o644)

    real_parent = trusted_token_dir / "real"
    real_parent.mkdir()
    parent_link = trusted_token_dir / "linked"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    nested = real_parent / "token"
    nested.write_bytes(b"x" * 32)
    assert run_token_preparer("prepare", parent_link / "token").returncode != 0
    assert nested.stat().st_gid == 0

    short = trusted_token_dir / "short"
    short.write_bytes(b"x" * 31)
    assert run_token_preparer("prepare", short).returncode != 0
    large = trusted_token_dir / "large"
    large.write_bytes(b"x" * 514)
    assert run_token_preparer("prepare", large).returncode != 0


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
def test_token_preparer_refuses_non_root_owner_without_mutation(trusted_token_dir):
    token = trusted_token_dir / "token"
    token.write_bytes(b"x" * 32)
    token.chmod(0o600)
    os.chown(token, 10003, 10003)

    prepared = run_token_preparer("prepare", token)

    assert prepared.returncode != 0
    info = token.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777) == (10003, 10003, 0o600)


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
def test_token_preparer_rejects_hardlink_without_mutating_alias(trusted_token_dir):
    token = trusted_token_dir / "token"
    alias = trusted_token_dir / "unrelated-alias"
    token.write_bytes(b"x" * 32)
    token.chmod(0o600)
    alias.hardlink_to(token)

    prepared = run_token_preparer("prepare", token)

    assert prepared.returncode != 0
    assert "hardlink" in prepared.stderr
    info = alias.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777, info.st_nlink) == (0, 0, 0o600, 2)


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
def test_token_preparer_rejects_untrusted_writable_parent_without_mutation(tmp_path):
    token = tmp_path / "token"
    token.write_bytes(b"x" * 32)
    token.chmod(0o600)

    prepared = run_token_preparer("prepare", token)

    assert prepared.returncode != 0
    assert "parent" in prepared.stderr
    info = token.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777) == (0, 0, 0o600)


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
def test_token_preparer_rejects_double_slash_path_without_mutation(trusted_token_dir):
    token = trusted_token_dir / "token"
    token.write_bytes(b"x" * 32)
    token.chmod(0o600)

    prepared = run_token_preparer("prepare", f"/{token}")

    assert prepared.returncode != 0
    assert "normalized" in prepared.stderr
    info = token.stat()
    assert (info.st_gid, info.st_mode & 0o777) == (0, 0o600)


@pytest.mark.skipif(os.geteuid() != 0, reason="token ownership contract requires root")
def test_token_preparer_detects_path_swap_and_does_not_mutate_symlink_target(
    trusted_token_dir, monkeypatch
):
    spec = importlib.util.spec_from_file_location("prepare_mieru_token", TOKEN_PREPARER_HELPER)
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    token = trusted_token_dir / "token"
    moved = trusted_token_dir / "moved-token"
    victim = trusted_token_dir / "victim"
    token.write_bytes(b"x" * 32)
    token.chmod(0o600)
    victim.write_bytes(b"v" * 32)
    victim.chmod(0o600)
    victim_before = victim.stat()
    real_fchmod = helper.os.fchmod

    def swap_after_fd_chmod(fd, mode):
        real_fchmod(fd, mode)
        token.rename(moved)
        token.symlink_to(victim)

    monkeypatch.setattr(helper.os, "fchmod", swap_after_fd_chmod)

    with pytest.raises(helper.TokenError, match="identity changed"):
        helper.prepare_or_verify("prepare", str(token))

    victim_after = victim.stat()
    assert (victim_after.st_uid, victim_after.st_gid, victim_after.st_mode) == (
        victim_before.st_uid,
        victim_before.st_gid,
        victim_before.st_mode,
    )


@pytest.mark.skipif(os.geteuid() != 0, reason="identity preflight requires root")
@pytest.mark.parametrize("reserved_gid", ["0", "10001", "10002", "10003", "10004", "10005"])
def test_state_preparer_rejects_reserved_mita_socket_gid(tmp_path, reserved_gid):
    result = subprocess.run(
        [str(STATE_PREPARER), "prepare", str(tmp_path / "state")],
        cwd=ROOT,
        env={**os.environ, "MIERU_MITA_GID": reserved_gid},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "MIERU_MITA_GID" in result.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason="container permission contract requires root")
def test_combined_panel_runtime_has_only_mieru_group_and_private_staged_token(
    tmp_path, trusted_token_dir
):
    tmp_path.chmod(0o755)
    token = trusted_token_dir / "mieru-token"
    token.write_bytes(b"m" * 32)
    token.chmod(0o600)
    mount = f"type=bind,src={token},dst=/run/secrets/mieru-manager-token,readonly"
    unreadable = subprocess.run(
        [
            "docker", "run", "--rm", "--entrypoint", "python", "--mount", mount,
            "mtproxy-mieru-manager:latest", "-c",
            "from pathlib import Path; Path('/run/secrets/mieru-manager-token').read_bytes()",
        ],
        capture_output=True,
        check=False,
    )
    assert unreadable.returncode != 0
    assert run_token_preparer("prepare", token).returncode == 0
    readable = subprocess.run(
        [
            "docker", "run", "--rm", "--entrypoint", "python", "--mount", mount,
            "mtproxy-mieru-manager:latest", "-c",
            "from pathlib import Path; assert len(Path('/run/secrets/mieru-manager-token').read_bytes()) == 32",
        ],
        capture_output=True,
        check=False,
    )
    assert readable.returncode == 0, readable.stderr.decode()

    telemt = tmp_path / "telemt-token"
    telemt.write_bytes(b"Bearer " + b"t" * 32)
    telemt.chmod(0o600)
    naive_run, mieru_run = tmp_path / "naive-run", tmp_path / "mieru-run"
    accounting, mieru_state = tmp_path / "accounting", tmp_path / "mieru-state"
    for directory in (naive_run, mieru_run, accounting, mieru_state):
        directory.mkdir()
    os.chown(naive_run, 10002, 101)
    os.chown(mieru_run, 10005, 10005)
    naive_run.chmod(0o770)
    mieru_run.chmod(0o770)
    os.chown(accounting, 10002, 10004)
    os.chown(mieru_state, 10005, 10005)
    accounting.chmod(0o700)
    mieru_state.chmod(0o700)
    naive_socket, mieru_socket = socket.socket(socket.AF_UNIX), socket.socket(socket.AF_UNIX)
    naive_socket.bind(str(naive_run / "manager.sock"))
    mieru_socket.bind(str(mieru_run / "manager.sock"))
    naive_socket.listen(1)
    mieru_socket.listen(1)
    os.chown(naive_run / "manager.sock", 10002, 101)
    os.chown(mieru_run / "manager.sock", 10005, 10005)
    (naive_run / "manager.sock").chmod(0o660)
    (mieru_run / "manager.sock").chmod(0o660)

    name = f"mtproxy-panel-mieru-test-{uuid.uuid4().hex[:12]}"
    command = [
        "docker", "run", "-d", "--name", name, "--group-add", "10005",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
        "--cap-add", "DAC_READ_SEARCH", "--cap-add", "FOWNER", "--cap-add", "SETGID",
        "--cap-add", "SETUID", "--security-opt", "no-new-privileges:true",
        "-e", "PANEL_SUPPLEMENTARY_GROUPS=10005",
        "-e", "MIERU_ENABLED=true",
        "-e", "TELEMT_API_TOKEN_SOURCE=/run/secrets/telemt-api-token",
        "-e", "MIERU_MANAGER_TOKEN_SOURCE=/run/secrets/mieru-manager-token",
        "--mount", f"type=bind,src={telemt},dst=/run/secrets/telemt-api-token,readonly",
        "--mount", mount,
        "--mount", f"type=bind,src={naive_run},dst=/run/naive-manager,readonly",
        "--mount", f"type=bind,src={mieru_run},dst=/run/mieru-manager,readonly",
        "--mount", f"type=bind,src={accounting},dst=/probe/accounting,readonly",
        "--mount", f"type=bind,src={mieru_state},dst=/probe/mieru-state,readonly",
        "mtproxy-panel:latest",
    ]
    try:
        started = subprocess.run(command, capture_output=True, check=False)
        assert started.returncode == 0, started.stderr.decode()
        time.sleep(1)
        status = subprocess.run(
            ["docker", "exec", name, "cat", "/proc/1/status"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        assert "Uid:\t10001\t10001\t10001\t10001" in status
        assert "Gid:\t101\t101\t101\t101" in status
        assert next(line for line in status.splitlines() if line.startswith("Groups:")) == "Groups:\t10005 "
        assert "CapEff:\t0000000000000000" in status
        assert "NoNewPrivs:\t1" in status
        staged = subprocess.run(
            ["docker", "exec", name, "stat", "-c", "%u:%g:%a", "/run/panel/mieru-manager-token"],
            text=True,
            capture_output=True,
            check=True,
        )
        assert staged.stdout.strip() == "10001:101:400"
        client = "import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1])"
        for path in ("/run/naive-manager/manager.sock", "/run/mieru-manager/manager.sock"):
            connected = subprocess.run(
                ["docker", "exec", name, "setpriv", "--reuid=10001", "--regid=101", "--groups", "10005", "python", "-c", client, path],
                capture_output=True,
                check=False,
            )
            assert connected.returncode == 0, connected.stderr.decode()
        for path in ("/probe/accounting", "/probe/mieru-state"):
            denied = subprocess.run(
                ["docker", "exec", name, "setpriv", "--reuid=10001", "--regid=101", "--groups", "10005", "test", "-r", path],
                check=False,
            )
            assert denied.returncode != 0
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        naive_socket.close()
        mieru_socket.close()
