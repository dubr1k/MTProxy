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
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
STATE = REPO / ".lab-state"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "mtproxy-installer-lab"
SCENARIOS = {
    "smoke": ("archive-integrity", "audit", "plan", "coexistence", "dns-tls-preflight", "secrets-scan"),
    "full": (
        "environment-preflight", "audit", "plan", "install", "docker-build", "repair", "idempotence",
        "secrets-scan", "dns-tls-preflight", "uninstall",
        "interrupted-install-recovery", "interrupted-uninstall-recovery",
        "coexistence",
    ),
}


def allocate_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def full_egress_policy() -> str:
    """Return the fail-closed nftables policy for full-mode package/image access."""
    rules = """ct state established,related accept
        oifname \"lo\" accept
        ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
        ip daddr 10.0.2.3 udp dport 53 accept
        ip daddr 10.0.2.3 tcp dport 53 accept
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } reject
        ip6 daddr { ::/128, ::1/128, 64:ff9b:1::/48, 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 } reject
        tcp dport { 80, 443 } accept
        reject"""
    forward_rules = rules.replace('        oifname "lo" accept\n', "")
    return f"""table inet mtproxy_lab_egress {{
    chain output {{
        type filter hook output priority -100; policy drop;
        {rules}
    }}
    chain forward {{
        type filter hook forward priority -100; policy drop;
        {forward_rules}
    }}
}}
"""


def user_data(mode: str, public_key: str) -> str:
    if mode not in SCENARIOS:
        raise ValueError(f"unsupported mode: {mode}")
    prefix = (
        "#cloud-config\nusers:\n  - default\n  - name: lab\n    groups: [sudo]\n"
        "    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    ssh_authorized_keys:\n"
        f"      - {public_key}\n"
        "ssh_pwauth: false\ndisable_root: true\npackage_update: false\n"
    )
    if mode == "smoke":
        return prefix + "runcmd:\n  - [ touch, /var/lib/cloud/instance/lab-ready ]\n"
    indented_policy = "\n".join(f"      {line}" for line in full_egress_policy().splitlines())
    return prefix + (
        "write_files:\n"
        "  - path: /etc/nftables.conf\n"
        "    permissions: '0600'\n"
        "    owner: root:root\n"
        "    content: |\n"
        "      include \"/etc/nftables.d/mtproxy-lab-egress.nft\"\n"
        "  - path: /etc/nftables.d/mtproxy-lab-egress.nft\n"
        "    permissions: '0600'\n"
        "    owner: root:root\n"
        "    content: |\n"
        f"{indented_policy}\n"
        "runcmd:\n"
        "  - nft -f /etc/nftables.d/mtproxy-lab-egress.nft\n"
        "  - systemctl enable nftables.service\n"
        "  - [ touch, /var/lib/cloud/instance/lab-ready ]\n"
    )


def qemu_command(disk: Path, seed: Path, key: Path, port: int, pid: Path, serial: Path, mode: str) -> list[str]:
    if mode not in SCENARIOS:
        raise ValueError(f"unsupported mode: {mode}")
    del key  # key is deliberately not attached to the VM; cloud-init gets only its public half.
    restrict = "on" if mode == "smoke" else "off"
    return [
        "qemu-system-x86_64", "-accel", "tcg", "-machine", "q35", "-cpu", "max",
        "-smp", "2", "-m", "3072", "-display", "none", "-daemonize",
        "-pidfile", str(pid), "-serial", f"file:{serial}",
        "-drive", f"file={disk},if=virtio,format=qcow2,discard=unmap",
        "-drive", f"file={seed},if=virtio,format=raw,readonly=on",
        "-nic", f"user,model=virtio-net-pci,restrict={restrict},hostfwd=tcp:127.0.0.1:{port}-:22",
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
    disk = STATE / "disk.qcow2"
    if force:
        disk.unlink(missing_ok=True)
        (STATE / "disk-mode").unlink(missing_ok=True)
        (STATE / "disk-unbooted").unlink(missing_ok=True)
    if not disk.exists():
        run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(disk), "20G"])
        (STATE / "disk-unbooted").write_text("unbooted\n")


def _write_seed(mode: str) -> None:
    key = STATE / "ssh-key"
    public_key = key.with_suffix(".pub").read_text().strip()
    seed = STATE / "seed.img"
    seed.unlink(missing_ok=True)
    user_data_path = STATE / "user-data"
    user_data_path.write_text(user_data(mode, public_key))
    (STATE / "meta-data").write_text("instance-id: mtproxy-installer-lab\nlocal-hostname: installer-lab\n")
    run(["cloud-localds", str(seed), str(user_data_path), str(STATE / "meta-data")])


def _state_port() -> int:
    return int((STATE / "ssh-port").read_text())


def ssh_command(remote: str, *, port: int | None = None) -> list[str]:
    return ["ssh", "-i", str(STATE / "ssh-key"), "-p", str(port or _state_port()),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"UserKnownHostsFile={STATE / 'known_hosts'}", "lab@127.0.0.1", remote]


def wait_for_readiness(timeout: int | float, probe_timeout: int | float = 10) -> None:
    deadline = time.monotonic() + timeout
    last_returncode = None
    last_probe_timed_out = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            attempt = subprocess.run(
                ssh_command("test -f /var/lib/cloud/instance/lab-ready"),
                capture_output=True,
                text=True,
                timeout=min(probe_timeout, remaining),
            )
        except subprocess.TimeoutExpired:
            last_probe_timed_out = True
            last_returncode = None
        else:
            last_probe_timed_out = False
            last_returncode = attempt.returncode
            if attempt.returncode == 0:
                return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(5, remaining))

    if last_probe_timed_out:
        detail = "last SSH readiness probe timed out"
    elif last_returncode is not None:
        detail = f"last SSH readiness probe exited {last_returncode}"
    else:
        detail = "no SSH readiness probe was attempted"
    raise TimeoutError(f"VM readiness timed out ({detail}); inspect {STATE / 'serial.log'}")


def start(mode: str, timeout: int = 900) -> None:
    if mode not in SCENARIOS:
        raise ValueError(f"unsupported mode: {mode}")
    prepare()
    pid_file = STATE / "qemu.pid"
    mode_file = STATE / "disk-mode"
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text()), 0)
            active_mode = mode_file.read_text().strip() if mode_file.exists() else "unknown"
            if active_mode != mode:
                raise RuntimeError(f"running VM mode is {active_mode}; stop and reset before {mode}")
            return
        except ValueError:
            pid_file.unlink(missing_ok=True)
        except OSError:
            pid_file.unlink(missing_ok=True)
    unbooted = STATE / "disk-unbooted"
    if not unbooted.exists():
        disk_mode = mode_file.read_text().strip() if mode_file.exists() else "legacy/unknown"
        if disk_mode != mode:
            raise RuntimeError(f"disk mode is {disk_mode}; reset is required before {mode}")
    _write_seed(mode)
    port = allocate_port()
    (STATE / "ssh-port").write_text(f"{port}\n")
    run(qemu_command(STATE / "disk.qcow2", STATE / "seed.img", STATE / "ssh-key", port,
                     pid_file, STATE / "serial.log", mode))
    mode_file.write_text(f"{mode}\n")
    unbooted.unlink(missing_ok=True)
    wait_for_readiness(timeout)


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


def finalize_results(mode: str, results: list[dict], returncode: int, elapsed: float) -> list[dict]:
    if mode not in SCENARIOS:
        raise ValueError(f"unsupported mode: {mode}")
    finalized = list(results)
    if mode == "full" and returncode != 0 and not finalized:
        finalized.append({
            "name": "environment-preflight", "status": "failed", "seconds": elapsed,
            "message": f"guest setup failed before scenarios (exit {returncode})",
        })
    seen = {item["name"] for item in finalized}
    for name in SCENARIOS[mode]:
        if name not in seen:
            finalized.append({"name": name, "status": "failed", "seconds": 0,
                              "message": "result missing (guest runner failed closed)"})
    if returncode != 0 and not any(item["status"] == "failed" for item in finalized):
        finalized.append({"name": "guest-runner", "status": "failed", "seconds": elapsed,
                          "message": f"exit {returncode}"})
    return finalized


def run_scenarios(mode: str, output_dir: Path) -> list[dict]:
    if mode not in SCENARIOS:
        raise ValueError(f"unsupported mode: {mode}")
    start(mode)
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
    results = finalize_results(mode, results, completed.returncode, elapsed)
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
    start_parser.add_argument("--mode", choices=sorted(SCENARIOS), required=True)
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
        if args.command == "prepare":
            prepare()
        elif args.command == "start":
            start(args.mode, args.timeout)
        elif args.command == "stop":
            stop()
        elif args.command == "reset":
            reset()
        elif args.command == "run":
            run_scenarios(args.mode, args.output)
        elif args.command == "cleanup":
            cleanup(args.purge_cache)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError, ValueError) as exc:
        print(f"LAB FAILED: {sanitize(str(exc))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
