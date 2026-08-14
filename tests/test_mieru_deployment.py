from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
STATE_PREPARER = ROOT / "scripts" / "prepare-mieru-state.sh"
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


def render_mieru_compose() -> dict:
    env = {
        **os.environ,
        "MIERU_PUBLIC_HOST": "mieru.example.com",
        "MIERU_MITA_BIN": "/opt/pinned/mita",
        "MIERU_MITA_SHA256": MITA_AMD64_EXECUTABLE_SHA256,
        "MIERU_MITA_GID": "321",
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
        "bind": {},
    }
    assert mounts["/run/mita"]["read_only"] is True
    assert manager["group_add"] == ["321"]
    assert manager["environment"]["MIERU_MITA_SHA256"] == MITA_AMD64_EXECUTABLE_SHA256
    assert manager["read_only"] is True
    assert manager["cap_drop"] == ["ALL"]
    assert manager["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-m",
        "mieru_manager.healthcheck",
    ]
    assert config["services"]["panel"]["depends_on"]["mieru-manager"]["condition"] == "service_healthy"


def test_mieru_overlay_has_only_intended_writable_runtime_mounts():
    manager = render_mieru_compose()["services"]["mieru-manager"]
    writable_targets = {
        item["target"] for item in manager["volumes"] if not item.get("read_only", False)
    }
    assert writable_targets == {"/var/lib/mieru-manager", "/run/mieru-manager"}
    assert manager["tmpfs"] == ["/tmp:size=8m,mode=0700"]
    assert manager["pids_limit"] == 128


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_prepare_fresh_state_allows_fixed_container_identity_to_write(tmp_path):
    state_dir = tmp_path / "state"
    assert STATE_PREPARER.exists(), "state preparation command is required"

    prepared = run_state_preparer("prepare", state_dir)

    assert prepared.returncode == 0, prepared.stderr
    info = state_dir.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777) == (10003, 10003, 0o700)
    probe = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "10003:10003",
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
    assert (state_dir / "probe").stat().st_uid == 10003


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_rejects_root_owned_state_directory(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode != 0
    assert "owner 10003:10003" in verified.stderr
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
    os.chown(state_dir, 10003, 10003)
    journal = state_dir / "journal.json"
    journal.write_text("restored journal must remain opaque to verifier")
    journal.chmod(0o600)
    os.chown(journal, 10003, 10003)

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode != 0
    assert "journal.key" in verified.stderr
    assert "co-restore" in verified.stderr


def owned_private_file(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)
    os.chown(path, 10003, 10003)


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_accepts_complete_restore_without_changing_recovery_files(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 10003, 10003)
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
    os.chown(backups, 10003, 10003)
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
    os.chown(state_dir, 10003, 10003)
    state_file = state_dir / "state.json"
    state_file.write_bytes(b"restored")
    state_file.chmod(0o600)

    verified = run_state_preparer("verify", state_dir)

    assert verified.returncode != 0
    assert "state.json must have owner 10003:10003" in verified.stderr
    assert state_file.stat().st_uid == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_verify_rejects_symlinked_recovery_file(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 10003, 10003)
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
    os.chown(state_dir, 10003, 10003)
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
