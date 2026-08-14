from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "panel" / "entrypoint.sh"


def run_entrypoint(tmp_path: Path, supplementary_groups: str | None, **extra_env: str) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    install_log = tmp_path / "install.log"
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    (bin_dir / "install").write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$INSTALL_LOG\"\n"
    )
    (bin_dir / "setpriv").write_text(
        "#!/bin/sh\nprintf 'MIERU_MANAGER_TOKEN_FILE=%s\\n' \"${MIERU_MANAGER_TOKEN_FILE-}\"\nprintf '%s\\n' \"$@\"\n"
    )
    for command in bin_dir.iterdir():
        command.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "INSTALL_LOG": str(install_log),
        "PANEL_RUNTIME_DIR": str(runtime_dir),
        **extra_env,
    }
    if supplementary_groups is None:
        env.pop("PANEL_SUPPLEMENTARY_GROUPS", None)
    else:
        env["PANEL_SUPPLEMENTARY_GROUPS"] = supplementary_groups
    return subprocess.run(
        ["/bin/sh", str(ENTRYPOINT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize("value", [None, ""])
def test_panel_entrypoint_clears_supplementary_groups_by_default(tmp_path: Path, value: str | None):
    result = run_entrypoint(tmp_path, value)

    assert result.returncode == 0, result.stderr
    assert "--clear-groups" in result.stdout.splitlines()
    assert "--init-groups" not in result.stdout
    assert "--keep-groups" not in result.stdout


def test_panel_entrypoint_sets_only_allowlisted_mieru_group(tmp_path: Path):
    result = run_entrypoint(tmp_path, "10005")

    assert result.returncode == 0, result.stderr
    arguments = result.stdout.splitlines()
    assert "--groups" in arguments
    assert arguments[arguments.index("--groups") + 1] == "10005"
    assert "--clear-groups" not in arguments
    assert "--init-groups" not in arguments
    assert "--keep-groups" not in arguments


def test_panel_entrypoint_stages_mieru_token_and_exports_private_target(tmp_path: Path):
    mieru_source = tmp_path / "mieru-source"
    mieru_source.write_bytes(b"m" * 32)
    mieru_source.chmod(0o440)
    os.chown(mieru_source, 0, 10005)

    result = run_entrypoint(
        tmp_path,
        "10005",
        MIERU_ENABLED="true",
        MIERU_MANAGER_TOKEN_SOURCE=str(mieru_source),
    )

    assert result.returncode == 0, result.stderr
    staged = tmp_path / "runtime" / "mieru-manager-token"
    info = staged.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777, info.st_nlink) == (10001, 101, 0o400, 1)
    assert staged.read_bytes() == b"m" * 32
    assert f"MIERU_MANAGER_TOKEN_FILE={staged}" in result.stdout


def test_panel_entrypoint_mieru_disabled_does_not_touch_present_source(tmp_path: Path):
    source = tmp_path / "present-but-invalid"
    source.write_bytes(b"short")

    result = run_entrypoint(
        tmp_path,
        None,
        MIERU_ENABLED="false",
        MIERU_MANAGER_TOKEN_SOURCE=str(source),
    )

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "runtime" / "mieru-manager-token").exists()
    assert "MIERU_MANAGER_TOKEN_FILE=" in result.stdout


@pytest.mark.parametrize("defect", ["owner", "group", "mode", "short", "large", "hardlink", "symlink"])
def test_panel_entrypoint_rejects_invalid_mieru_source_before_any_staging(tmp_path: Path, defect: str):
    source = tmp_path / "mieru-source"
    source.write_bytes(b"m" * (514 if defect == "large" else 31 if defect == "short" else 32))
    source.chmod(0o440 if defect != "mode" else 0o600)
    os.chown(source, 10003 if defect == "owner" else 0, 0 if defect == "group" else 10005)
    if defect == "hardlink":
        (tmp_path / "alias").hardlink_to(source)
    elif defect == "symlink":
        target = source
        source = tmp_path / "source-link"
        source.symlink_to(target)

    result = run_entrypoint(
        tmp_path,
        "10005",
        MIERU_ENABLED="true",
        MIERU_MANAGER_TOKEN_SOURCE=str(source),
    )

    assert result.returncode == 64
    assert not (tmp_path / "install.log").exists()
    assert not (tmp_path / "runtime" / "mieru-manager-token").exists()


def test_invalid_groups_fail_before_mieru_source_validation(tmp_path: Path):
    result = run_entrypoint(
        tmp_path,
        "10004",
        MIERU_ENABLED="true",
        MIERU_MANAGER_TOKEN_SOURCE=str(tmp_path / "missing"),
    )

    assert result.returncode == 64
    assert "PANEL_SUPPLEMENTARY_GROUPS" in result.stderr
    assert "Mieru" not in result.stderr


@pytest.mark.parametrize(
    "value",
    ["0", "10003", "10005,10005", "10005,10004", "10004", " 10005", "10005 ", "10005,", ",10005", "root", "+10005", "010005"],
)
def test_panel_entrypoint_rejects_non_allowlisted_or_malformed_groups_before_launch(
    tmp_path: Path, value: str
):
    result = run_entrypoint(tmp_path, value)

    assert result.returncode != 0
    assert "PANEL_SUPPLEMENTARY_GROUPS" in result.stderr
    assert result.stdout == ""
