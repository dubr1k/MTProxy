# Validation gates

## Required repository gates

```sh
python3 -m venv .venv
.venv/bin/pip install -r panel/requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
python3 -m unittest -v tests/test_deploy.py
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
python3 scripts/check-doc-links.py
```

CI also renders core, core+Naive, core+Mieru, combined core+Naive+Mieru, agent and fleet-central Compose models, plus the documented Mieru render with an executable placeholder and an empty secret file. It builds panel/managers/agents/ingress and the pinned Caddy+forward-proxy artifact, executes the bounded Caddy checker against that artifact and a negative fixture, verifies service units where host tooling permits, and enforces diff hygiene and third-party notices.

## Runtime acceptance

Validate Nginx before reload, public listener ownership, all adjacent SNI routes, authenticated manager boundaries, backups and rollback. MTProto requires Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ` for every secret. Naive requires cover HTTPS, authenticated CONNECT, completed-log collection and failure tests. Mieru requires executable digest/version, UDS/state preflight, transaction recovery and TCP/UDP checks. Fleet requires negative mTLS tests, certificate binding/revocation, ordered command/result durability, and no public local management API.

## Runtime evidence and pending gates

Telemt/MTProto, NaiveProxy/Caddy and Mieru/mita have each passed live end-to-end protocol probes on an operator-controlled deployment, including manager health and panel integration. This evidence does not make host-specific credentials, names, addresses or logs public and does not replace validation on a new target host.

A reproducible Ubuntu 24.04 QEMU install → audit → repair → upgrade → uninstall → rollback workflow remains pending and is not a required CI gate. Production fleet ingress/enrollment also remains pending until mTLS authorization and a durable command/result cycle are independently confirmed.
