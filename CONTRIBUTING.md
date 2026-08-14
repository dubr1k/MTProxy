# Contributing to Proxy Control

## Before opening an issue

Search existing reports and remove credentials, access links, QR codes, certificates, public IPs, production hostnames and unsanitized logs. Security vulnerabilities belong in the private reporting path described in [SECURITY.md](SECURITY.md).

## Development

Use Python 3.12 on Ubuntu 24.04 where possible:

```sh
python3 -m venv .venv
.venv/bin/pip install -r panel/requirements-dev.txt
.venv/bin/pytest -q
.venv/bin/ruff check .
python3 -m unittest -v tests/test_deploy.py
bash -n $(git ls-files '*.sh')
shellcheck $(git ls-files '*.sh')
python3 scripts/check-doc-links.py
```

Render every affected Compose combination and build affected images. The exact CI model and environment placeholders are in `.github/workflows/test.yml`.

## Architecture rules

- Preserve migration-sensitive paths, Compose names/volumes, unit filenames, commands and fleet URI identifiers documented in [COMPATIBILITY.md](docs/COMPATIBILITY.md).
- Keep protocol-specific MTProxy keys and names where they describe MTProto.
- Keep Mieru/mita as an external GPLv3+ process; do not copy GPL source/generated stubs into the MIT adapter.
- Do not widen manager APIs, mount a Docker socket, expose management ports, weaken fail-closed transactions, or invent accounting precision.
- Require explicit production hostnames and secret input; examples use RFC domains.

## Pull requests

Create a focused branch, add regression tests before/following the fix, update both README languages when their shared structure changes, and complete the PR checklist. Explain security boundaries, compatibility impact, rollback, accounting impact, and validation evidence. Keep generated/private files out of Git and ensure `git diff --check` is clean.

Contributions are accepted under the repository MIT license unless explicitly agreed otherwise. Third-party material must include verified provenance and compatible notices; do not change `LICENSE` copyright text as a drive-by edit.
