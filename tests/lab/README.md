# Isolated Ubuntu 24.04 installer lab

This lab boots an official, checksum-pinned Ubuntu 24.04 cloud image in QEMU. It does not use KVM, TAP, bridges, host firewall rules, host Docker, or production credentials. QEMU always uses TCG, two virtual CPUs, 3 GiB RAM, a disposable qcow2 overlay, and restricted user-mode networking. The only inbound mapping is a checked random loopback TCP port forwarded to guest SSH.

## Prerequisites

Ubuntu host packages: `qemu-system-x86`, `qemu-utils`, `cloud-image-utils`, `openssh-client`, `curl`, `shellcheck`, and Python 3. The guest needs outbound package/image access only in `full` mode. No ACME request is made: the full fixture injects a local deterministic Certbot-compatible certificate generator, and DNS is supplied through guest-only `/etc/hosts` entries.

## Commands

```bash
make lab-test       # host helper tests, Bash parse check, ShellCheck
make lab-prepare    # verify/download pinned base; create key, seed, overlay
make lab-start      # boot and wait for cloud-init/SSH readiness
make lab-smoke      # real VM: archive, audit, plan, fixtures, report
make lab-reset      # stop and create a fresh overlay/ephemeral key
make lab-full       # all lifecycle, recovery, coexistence, Docker scenarios
make lab-stop
make lab-clean      # remove all lab-created state; retain pinned base cache
```

Direct CLI equivalents are available through `python3 scripts/lab/qemu_lab.py {prepare,start,reset,run,stop,cleanup}`. Add `cleanup --purge-cache` to delete the verified base image too. `run --output PATH` writes sanitized `report.json`, JUnit `report.xml`, and `guest.log` outside the guest. Any missing result, failed guest command, checksum mismatch, readiness timeout, or failed assertion exits nonzero.

## Modes and isolation

`smoke` is intended for TCG CI and normally completes without guest package installation. It copies `git archive HEAD` exactly into the guest, verifies the archive digest, then exercises audit/plan against deterministic Nginx/Xray/DNS/TLS fixtures and proves they remain byte-identical.

`full` installs Nginx, Docker/Compose, and test dependencies inside the disposable VM. It runs audit, plan, install, repair, repeat-install idempotence, uninstall twice, SIGKILL-based interrupted install/uninstall recovery, shared-443/Xray/3x-ui/WARP preservation, local DNS/TLS preflight, Compose image build verification, package/manifest checks, listener checks, and artifact secret scans. It can take well over an hour under TCG. Run `make lab-reset` before an independent full validation.

The base cache is `${XDG_CACHE_HOME:-~/.cache}/mtproxy-installer-lab`. All mutable state and private ephemeral SSH keys are under ignored `.lab-state/`; reports are under ignored `lab-results/`. The private key is never attached as a VM drive and no production secret is embedded.
