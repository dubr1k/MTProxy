from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "probe" / "mtproxy-respq-probe"


def run_wrapper(tmp_path: Path, *args: str, euid: int = 0) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.args"
    (bin_dir / "id").write_text(f"#!/bin/sh\n[ \"$1\" = -u ] && printf '%s\\n' {euid}\n")
    (bin_dir / "docker").write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$DOCKER_LOG\"\nprintf '%s\\n' 'probe: verified 2 configured proxy secret(s)'\n"
    )
    (bin_dir / "stat").write_text(
        "#!/bin/sh\ncase \"$2\" in '%u') printf '%s\\n' 0 ;; '%a') printf '%s\\n' 600 ;; esac\n"
    )
    for executable in bin_dir.iterdir():
        executable.chmod(0o755)
    environment = os.environ | {"PATH": f"{bin_dir}:{os.environ['PATH']}", "DOCKER_LOG": str(docker_log)}
    return subprocess.run(
        [str(WRAPPER), *args], text=True, capture_output=True, env=environment, check=False
    )


def test_wrapper_rejects_invalid_arguments_without_starting_docker(tmp_path: Path):
    result = run_wrapper(tmp_path, "--domain", "not a domain", "--secrets-file", "/missing")

    assert result.returncode != 0
    assert "usage:" in result.stderr
    assert not (tmp_path / "docker.args").exists()


def test_wrapper_mounts_secret_file_read_only_without_placing_secret_in_docker_argv(tmp_path: Path):
    secret = "0123456789abcdef0123456789abcdef"
    secrets_file = tmp_path / "users.conf"
    secrets_file.write_text(f"owner={secret}\nphone=fedcba9876543210fedcba9876543210\n")
    secrets_file.chmod(0o600)

    result = run_wrapper(
        tmp_path,
        "--domain",
        "proxy.example.com",
        "--secrets-file",
        str(secrets_file),
    )

    assert result.returncode == 0, result.stderr
    docker_args = (tmp_path / "docker.args").read_text()
    assert "run\n--rm\n--network\nhost\n--read-only\n" in docker_args
    assert f"type=bind,src={secrets_file},dst=/run/mtproxy/users.conf,readonly" in docker_args
    assert "--domain\nproxy.example.com\n--secrets-file\n/run/mtproxy/users.conf\n" in docker_args
    assert secret not in docker_args
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_wrapper_requires_root(tmp_path: Path):
    secrets_file = tmp_path / "users.conf"
    secrets_file.write_text("owner=0123456789abcdef0123456789abcdef\n")
    secrets_file.chmod(0o600)

    result = run_wrapper(
        tmp_path,
        "--domain",
        "proxy.example.com",
        "--secrets-file",
        str(secrets_file),
        euid=1000,
    )

    assert result.returncode != 0
    assert "must run as root" in result.stderr
    assert not (tmp_path / "docker.args").exists()
