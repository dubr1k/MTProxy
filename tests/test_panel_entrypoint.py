from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from panel import stage_secret


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "panel" / "entrypoint.sh"
RUNTIME_DIR = "/run/panel"
TELEMT_TARGET = f"{RUNTIME_DIR}/telemt-api-token"
NAIVE_TARGET = f"{RUNTIME_DIR}/naive-manager-token"
MIERU_TARGET = f"{RUNTIME_DIR}/mieru-manager-token"


def _fake_command(command: str) -> str:
    return f"""#!/bin/sh
{{
  printf '{command}'
  for argument do
    printf '\\t%s' "$argument"
  done
  printf '\\n'
}} >> "$COMMAND_LOG"
"""


def run_entrypoint(
    tmp_path: Path,
    supplementary_groups: str | None,
    *,
    python3_exit: int = 0,
    **extra_env: str,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    command_log = tmp_path / "commands.log"
    environment_log = tmp_path / "environment.log"
    runtime_override = tmp_path / "runtime-override"
    runtime_override.mkdir()
    for token_name in ("telemt-api-token", "naive-manager-token", "mieru-manager-token"):
        (runtime_override / token_name).write_text("sentinel")

    for command in ("install", "rm", "python3", "setpriv"):
        script = _fake_command(command)
        if command == "python3":
            script += 'exit "$FAKE_PYTHON3_EXIT"\n'
        elif command == "setpriv":
            script += """printf '%s\n' \
  "${TELEMT_API_TOKEN_FILE-}" \
  "${NAIVE_MANAGER_TOKEN_FILE-}" \
  "${MIERU_MANAGER_TOKEN_FILE-}" > "$ENVIRONMENT_LOG"
"""
        (bin_dir / command).write_text(script)
        (bin_dir / command).chmod(0o755)

    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "COMMAND_LOG": str(command_log),
        "ENVIRONMENT_LOG": str(environment_log),
        "FAKE_PYTHON3_EXIT": str(python3_exit),
        # This attacker-controlled value must have no effect on privileged destinations.
        "PANEL_RUNTIME_DIR": str(runtime_override),
        **extra_env,
    }
    if supplementary_groups is not None:
        env["PANEL_SUPPLEMENTARY_GROUPS"] = supplementary_groups

    result = subprocess.run(
        ["/bin/sh", str(ENTRYPOINT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    result.command_log = command_log  # type: ignore[attr-defined]
    result.environment_log = environment_log  # type: ignore[attr-defined]
    result.runtime_override = runtime_override  # type: ignore[attr-defined]
    return result


def logged_commands(result: subprocess.CompletedProcess[str]) -> list[list[str]]:
    command_log: Path = result.command_log  # type: ignore[attr-defined]
    if not command_log.exists():
        return []
    return [line.split("\t") for line in command_log.read_text().splitlines()]


@pytest.mark.parametrize("value", [None, ""])
def test_panel_entrypoint_clears_supplementary_groups_by_default(tmp_path: Path, value: str | None):
    result = run_entrypoint(tmp_path, value)

    assert result.returncode == 0, result.stderr
    launch = logged_commands(result)[-1]
    assert launch[0] == "setpriv"
    assert "--clear-groups" in launch
    assert "--init-groups" not in launch
    assert "--keep-groups" not in launch


def test_panel_entrypoint_sets_only_allowlisted_mieru_group(tmp_path: Path):
    result = run_entrypoint(tmp_path, "10005")

    assert result.returncode == 0, result.stderr
    launch = logged_commands(result)[-1]
    assert launch[0] == "setpriv"
    assert launch[launch.index("--groups") + 1] == "10005"
    assert "--clear-groups" not in launch
    assert "--init-groups" not in launch
    assert "--keep-groups" not in launch

def test_panel_entrypoint_sets_agent_and_mieru_groups(tmp_path: Path):
    result = run_entrypoint(tmp_path, "10001,10005")

    assert result.returncode == 0, result.stderr
    launch = logged_commands(result)[-1]
    assert launch[launch.index("--groups") + 1] == "10001,10005"
    assert "--clear-groups" not in launch
    assert "--init-groups" not in launch
    assert "--keep-groups" not in launch


def test_panel_entrypoint_ignores_runtime_override_and_uses_fixed_privileged_destinations(
    tmp_path: Path,
):
    mieru_source = tmp_path / "mieru-source"
    mieru_source.write_text("source")
    naive_source = tmp_path / "naive-source"
    naive_source.write_text("source")

    result = run_entrypoint(
        tmp_path,
        "10005",
        MIERU_ENABLED="true",
        MIERU_MANAGER_TOKEN_SOURCE=str(mieru_source),
        NAIVE_MANAGER_TOKEN_SOURCE=str(naive_source),
        TELEMT_API_TOKEN_FILE=str(tmp_path / "attacker-telemt-target"),
        NAIVE_MANAGER_TOKEN_FILE=str(tmp_path / "attacker-naive-target"),
        MIERU_MANAGER_TOKEN_FILE=str(tmp_path / "attacker-mieru-target"),
    )

    assert result.returncode == 0, result.stderr
    assert (result.runtime_override / "mieru-manager-token").read_text() == "sentinel"  # type: ignore[attr-defined]
    assert {path.name: path.read_text() for path in result.runtime_override.iterdir()} == {  # type: ignore[attr-defined]
        "telemt-api-token": "sentinel",
        "naive-manager-token": "sentinel",
        "mieru-manager-token": "sentinel",
    }
    assert logged_commands(result) == [
        ["python3", str(ROOT / "panel" / "stage_secret.py"), "verify", str(mieru_source)],
        ["install", "-d", "-m", "0700", "-o", "panel", "-g", "panel", RUNTIME_DIR],
        [
            "install",
            "-m",
            "0400",
            "-o",
            "panel",
            "-g",
            "panel",
            "/run/secrets/telemt-api-token",
            TELEMT_TARGET,
        ],
        ["install", "-m", "0400", "-o", "panel", "-g", "panel", str(naive_source), NAIVE_TARGET],
        ["rm", "-f", "--", MIERU_TARGET],
        [
            "python3",
            str(ROOT / "panel" / "stage_secret.py"),
            "stage",
            str(mieru_source),
            MIERU_TARGET,
        ],
        [
            "setpriv",
            "--reuid=panel",
            "--regid=panel",
            "--groups",
            "10005",
            "--no-new-privs",
            "uvicorn",
            "panel.app:create_app",
            "--factory",
            "--host",
            "0.0.0.0",
            "--port",
            "8787",
            "--proxy-headers",
            "--forwarded-allow-ips",
            "172.16.0.0/12",
        ],
    ]
    assert result.environment_log.read_text().splitlines() == [  # type: ignore[attr-defined]
        TELEMT_TARGET,
        NAIVE_TARGET,
        MIERU_TARGET,
    ]


def test_panel_entrypoint_mieru_disabled_does_not_verify_stage_or_remove_token(tmp_path: Path):
    result = run_entrypoint(
        tmp_path,
        None,
        MIERU_ENABLED="false",
        MIERU_MANAGER_TOKEN_SOURCE=str(tmp_path / "present-but-invalid"),
    )

    assert result.returncode == 0, result.stderr
    commands = logged_commands(result)
    assert all(command[0] not in {"python3", "rm"} for command in commands)


def test_panel_entrypoint_mieru_validation_failure_precedes_all_staging(tmp_path: Path):
    source = tmp_path / "invalid-source"
    result = run_entrypoint(
        tmp_path,
        "10005",
        python3_exit=64,
        MIERU_ENABLED="true",
        MIERU_MANAGER_TOKEN_SOURCE=str(source),
    )

    assert result.returncode == 64
    assert logged_commands(result) == [
        ["python3", str(ROOT / "panel" / "stage_secret.py"), "verify", str(source)]
    ]


def test_invalid_groups_fail_before_mieru_source_validation(tmp_path: Path):
    result = run_entrypoint(
        tmp_path,
        "10004",
        python3_exit=64,
        MIERU_ENABLED="true",
        MIERU_MANAGER_TOKEN_SOURCE=str(tmp_path / "missing"),
    )

    assert result.returncode == 64
    assert "PANEL_SUPPLEMENTARY_GROUPS" in result.stderr
    assert logged_commands(result) == []


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "10003",
        "10005,10005",
        "10005,10004",
        "10004",
        " 10005",
        "10005 ",
        "10005,",
        ",10005",
        "root",
        "+10005",
        "010005",
    ],
)
def test_panel_entrypoint_rejects_non_allowlisted_or_malformed_groups_before_launch(
    tmp_path: Path, value: str
):
    result = run_entrypoint(tmp_path, value)

    assert result.returncode == 64
    assert "PANEL_SUPPLEMENTARY_GROUPS" in result.stderr
    assert logged_commands(result) == []


def test_stage_secret_stages_real_file_with_private_metadata(tmp_path: Path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"m" * 32)
    source.chmod(stage_secret.SOURCE_MODE)
    os.chown(source, stage_secret.SOURCE_UID, stage_secret.SOURCE_GID)

    stage_secret.stage(str(source), str(destination))

    info = destination.stat()
    assert destination.read_bytes() == b"m" * 32
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777, info.st_nlink) == (
        10001,
        101,
        0o400,
        1,
    )


@pytest.mark.parametrize("defect", ["owner", "group", "mode", "short", "large", "hardlink", "symlink"])
def test_stage_secret_rejects_invalid_source_without_creating_destination(
    tmp_path: Path, defect: str
):
    source = tmp_path / "source"
    source.write_bytes(b"m" * (514 if defect == "large" else 31 if defect == "short" else 32))
    source.chmod(0o440 if defect != "mode" else 0o600)
    os.chown(source, 10003 if defect == "owner" else 0, 0 if defect == "group" else 10005)
    if defect == "hardlink":
        (tmp_path / "alias").hardlink_to(source)
    elif defect == "symlink":
        target = source
        source = tmp_path / "source-link"
        source.symlink_to(target)
    destination = tmp_path / "destination"

    with pytest.raises((OSError, stage_secret.StageError)):
        stage_secret.stage(str(source), str(destination))

    assert not destination.exists()
