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

    result = run_entrypoint(
        tmp_path,
        "10005",
        MIERU_MANAGER_TOKEN_SOURCE=str(mieru_source),
    )

    assert result.returncode == 0, result.stderr
    install_arguments = (tmp_path / "install.log").read_text().splitlines()
    source_index = install_arguments.index(str(mieru_source))
    assert install_arguments[source_index - 6 : source_index + 2] == [
        "-m",
        "0400",
        "-o",
        "panel",
        "-g",
        "panel",
        str(mieru_source),
        "/run/panel/mieru-manager-token",
    ]
    assert "MIERU_MANAGER_TOKEN_FILE=/run/panel/mieru-manager-token" in result.stdout


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
