# Validation gates

## Required repository gates

```sh
python3 -m venv .venv
.venv/bin/pip install -r panel/requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
python3 -m unittest -v tests/test_deploy.py
bash -n $(git ls-files '*.sh')
shellcheck $(git ls-files '*.sh')
python3 scripts/check-doc-links.py
```

CI also renders core, core+Naive, core+Mieru, agent and fleet-central Compose models; builds panel/managers/agents/ingress; verifies service units where host tooling permits; and enforces diff hygiene and third-party notices.

## Runtime acceptance

Validate Nginx before reload, public listener ownership, all adjacent SNI routes, authenticated manager boundaries, backups and rollback. MTProto requires Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ` for every secret. Naive requires cover HTTPS, authenticated CONNECT, completed-log collection and failure tests. Mieru requires executable digest/version, UDS/state preflight, transaction recovery and TCP/UDP checks. Fleet requires negative mTLS tests, certificate binding/revocation, ordered command/result durability, and no public local management API.

## Pending gates

A reproducible Ubuntu 24.04 QEMU install → audit → repair → upgrade → uninstall → rollback workflow is pending and is not required CI. Production Mieru deployment and fleet enrollment also remain pending until independently confirmed.
