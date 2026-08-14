#!/usr/bin/env python3
"""Host-side controller for the isolated Ubuntu QEMU installer lab."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
STATE = REPO / ".lab-state"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "mtproxy-installer-lab"
SCENARIOS = {
    "smoke": ("archive-integrity", "audit", "plan", "coexistence", "dns-tls-preflight", "secrets-scan"),
    "full": (
        "audit", "plan", "install", "repair", "idempotence", "uninstall",
        "interrupted-install-recovery", "interrupted-uninstall-recovery",
        "coexistence", "dns-tls-preflight", "docker-build", "secrets-scan",
    ),
}


def allocate_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def qemu_command(disk: Path, seed: Path, key: Path, port: int, pid: Path, serial: Path) -> list[str]:
    del key  # key is deliberately not attached to the VM; cloud-init gets only its public half.
    return [
        "qemu-system-x86_64", "-accel", "tcg", "-machine", "q35", "-cpu", "max",
        "-smp", "2", "-m", "3072", "-display", "none", "-daemonize",
        "-pidfile", str(pid), "-serial", f"file:{serial}",
        "-drive", f"file={disk},if=virtio,format=qcow2,discard=unmap",
        "-drive", f"file={seed},if=virtio,format=raw,readonly=on",
        "-nic", f"user,model=virtio-net-pci,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:22",
    ]


def sanitize(text: str) -> str:
    patterns = (
        r"(?i)(password\s*[=:]\s*)\S+",
        r"(?i)(telemt-api-token\s*[=:]\s*)\S+",
        r"(?i)(secret\s*[=:]\s*)\S+",
        r"(?:tg|https)://(?:t\.me/)?proxy\?\S+",
    )
    clean = text
    for pattern in patterns:
        clean = re.sub(pattern, lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]", clean)
    return clean


def junit_xml(results: list[dict]) -> str:
    failures = sum(item["status"] != "passed" for item in results)
    elapsed = sum(float(item.get("seconds", 0)) for item in results)
    lines = [f'<testsuite name="qemu-installer-lab" tests="{len(results)}" failures="{failures}" time="{elapsed:.3f}">']
    for item in results:
        name = html.escape(str(item["name"]), quote=True)
        seconds = float(item.get("seconds", 0))
        lines.append(f'  <testcase classname="installer.lab" name="{name}" time="{seconds:.3f}">')
        if item["status"] != "passed":
            message = html.escape(sanitize(str(item.get("message", "scenario failed"))), quote=True)
            lines.append(f'    <failure message="{message}"/>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    return "\n".join(lines) + "\n"


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, **kwargs)


def metadata() -> dict:
    return json.loads((HERE / "image.json").read_text())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare(force: bool = False) -> None:
    STATE.mkdir(mode=0o700, exist_ok=True)
    CACHE.mkdir(mode=0o755, parents=True, exist_ok=True)
    image = CACHE / "ubuntu-24.04-amd64.img"
    info = metadata()
    if not image.exists() or sha256(image) != info["sha256"]:
        image.unlink(missing_ok=True)
        partial = image.with_suffix(".partial")
        run(["curl", "--fail", "--location", "--retry", "3", "--output", str(partial), info["url"]])
        if sha256(partial) != info["sha256"]:
            partial.unlink(missing_ok=True)
            raise RuntimeError("official Ubuntu image checksum mismatch")
        partial.replace(image)
    key = STATE / "ssh-key"
    if force:
        key.unlink(missing_ok=True)
        key.with_suffix(".pub").unlink(missing_ok=True)
    if not key.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "qemu-installer-lab", "-f", str(key)])
    os.chmod(key, 0o600)
    user_data = STATE / "user-data"
    user_data.write_text(
        "#cloud-config\nusers:\n  - default\n  - name: lab\n    groups: [sudo]\n"
        "    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    ssh_authorized_keys:\n"
        f"      - {key.with_suffix('.pub').read_text().strip()}\n"
        "ssh_pwauth: false\ndisable_root: true\npackage_update: false\n"
        "runcmd:\n  - [ touch, /var/lib/cloud/instance/lab-ready ]\n"
    )
    (STATE / "meta-data").write_text("instance-id: mtproxy-installer-lab\nlocal-hostname: installer-lab\n")
    run(["cloud-localds", str(STATE / "seed.img"), str(user_data), str(STATE / "meta-data")])
    disk = STATE / "disk.qcow2"
    if force:
        disk.unlink(missing_ok=True)
    if not disk.exists():
        run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(disk), "20G"])


def _state_port() -> int:
    return int((STATE / "ssh-port").read_text())


def ssh_command(remote: str, *, port: int | None = None) -> list[str]:
    return ["ssh", "-i", str(STATE / "ssh-key"), "-p", str(port or _state_port()),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", f"UserKnownHostsFile={STATE / 'known_hosts'}", "lab@127.0.0.1", remote]


def start(timeout: int = 900) -> None:
    prepare()
    pid_file = STATE / "qemu.pid"
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text()), 0)
            return
        except (OSError, ValueError):
            pid_file.unlink(missing_ok=True)
    port = allocate_port()
    (STATE / "ssh-port").write_text(f"{port}\n")
    run(qemu_command(STATE / "disk.qcow2", STATE / "seed.img", STATE / "ssh-key", port, pid_file, STATE / "serial.log"))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        attempt = subprocess.run(ssh_command("test -f /var/lib/cloud/instance/lab-ready"), capture_output=True, text=True)
        if attempt.returncode == 0:
            return
        time.sleep(5)
    raise TimeoutError(f"VM readiness timed out; inspect {STATE / 'serial.log'}")


def stop() -> None:
    pid_file = STATE / "qemu.pid"
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text())
        os.kill(pid, 15)
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.1)
        else:
            os.kill(pid, 9)
    except (OSError, ValueError):
        pass
    pid_file.unlink(missing_ok=True)


def reset() -> None:
    stop()
    for name in ("disk.qcow2", "seed.img", "user-data", "meta-data", "ssh-port", "known_hosts", "serial.log"):
        (STATE / name).unlink(missing_ok=True)
    prepare(force=True)


def _archive() -> tuple[Path, str]:
    archive = STATE / "source.tar"
    with archive.open("wb") as output:
        subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=REPO, check=True, stdout=output)
    return archive, sha256(archive)


def guest_remote(mode: str, archive_hash: str) -> str:
    return (
        "set -eu; rm -rf /tmp/mtproxy-source; mkdir /tmp/mtproxy-source; "
        "tar -xf /tmp/mtproxy-source.tar -C /tmp/mtproxy-source; "
        f"sudo bash /tmp/mtproxy-source/scripts/lab/guest-runner.sh {mode} {archive_hash}"
    )


def run_scenarios(mode: str, output_dir: Path) -> list[dict]:
    if mode not in SCENARIOS:
        raise ValueError(f"unsupported mode: {mode}")
    start()
    archive, archive_hash = _archive()
    remote_archive = "/tmp/mtproxy-source.tar"
    run(["scp", "-q", "-i", str(STATE / "ssh-key"), "-P", str(_state_port()),
         "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={STATE / 'known_hosts'}",
         str(archive), f"lab@127.0.0.1:{remote_archive}"])
    remote = guest_remote(mode, archive_hash)
    started = time.monotonic()
    completed = subprocess.run(ssh_command(remote), capture_output=True, text=True)
    elapsed = time.monotonic() - started
    log = sanitize(completed.stdout + completed.stderr)
    results = []
    for line in completed.stdout.splitlines():
        if not line.startswith("LAB_RESULT\t"):
            continue
        _prefix, name, status, seconds, message = (line.split("\t", 4) + [""])[:5]
        results.append({"name": name, "status": status, "seconds": float(seconds), "message": sanitize(message)})
    seen = {item["name"] for item in results}
    for name in SCENARIOS[mode]:
        if name not in seen:
            results.append({"name": name, "status": "failed", "seconds": 0, "message": "result missing (guest runner failed closed)"})
    if completed.returncode != 0 and not any(item["status"] == "failed" for item in results):
        results.append({"name": "guest-runner", "status": "failed", "seconds": elapsed, "message": f"exit {completed.returncode}"})
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {"schema": 1, "mode": mode, "image": metadata(), "archive_sha256": archive_hash,
               "elapsed_seconds": round(elapsed, 3), "results": results}
    (output_dir / "report.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    (output_dir / "report.xml").write_text(junit_xml(results))
    (output_dir / "guest.log").write_text(log)
    if completed.returncode or any(item["status"] != "passed" for item in results):
        raise RuntimeError(f"{mode} lab failed; see {output_dir}")
    return results


def cleanup(purge_cache: bool = False) -> None:
    stop()
    shutil.rmtree(STATE, ignore_errors=True)
    if purge_cache:
        shutil.rmtree(CACHE, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    start_parser = sub.add_parser("start")
    start_parser.add_argument("--timeout", type=int, default=900)
    sub.add_parser("stop")
    sub.add_parser("reset")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--mode", choices=sorted(SCENARIOS), default="smoke")
    run_parser.add_argument("--output", type=Path, default=REPO / "lab-results")
    cleanup_parser = sub.add_parser("cleanup")
    cleanup_parser.add_argument("--purge-cache", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare": prepare()
        elif args.command == "start": start(args.timeout)
        elif args.command == "stop": stop()
        elif args.command == "reset": reset()
        elif args.command == "run": run_scenarios(args.mode, args.output)
        elif args.command == "cleanup": cleanup(args.purge_cache)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError, ValueError) as exc:
        print(f"LAB FAILED: {sanitize(str(exc))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
