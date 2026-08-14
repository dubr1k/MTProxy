from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "panel" / "entrypoint.sh"


def run_entrypoint(tmp_path: Path, supplementary_groups: str | None) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "install").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "setpriv").write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    for command in bin_dir.iterdir():
        command.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
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
    result = run_entrypoint(tmp_path, "10003")

    assert result.returncode == 0, result.stderr
    arguments = result.stdout.splitlines()
    assert "--groups" in arguments
    assert arguments[arguments.index("--groups") + 1] == "10003"
    assert "--clear-groups" not in arguments
    assert "--init-groups" not in arguments
    assert "--keep-groups" not in arguments


@pytest.mark.parametrize(
    "value",
    ["0", "10003,10003", "10003,10004", "10004", " 10003", "10003 ", "10003,", ",10003", "root", "+10003", "010003"],
)
def test_panel_entrypoint_rejects_non_allowlisted_or_malformed_groups_before_launch(
    tmp_path: Path, value: str
):
    result = run_entrypoint(tmp_path, value)

    assert result.returncode != 0
    assert "PANEL_SUPPLEMENTARY_GROUPS" in result.stderr
    assert result.stdout == ""
