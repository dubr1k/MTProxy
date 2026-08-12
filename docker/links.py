#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import quote


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, value = line.split("=", 1)
        values[name] = value
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description="Print per-user MTProxy links")
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--secrets", type=Path, default=Path("secrets/users.conf"))
    args = parser.parse_args()

    domain_hex = args.domain.encode().hex()
    for name, secret in load_env(args.secrets).items():
        ee_secret = f"ee{secret.lower()}{domain_hex}"
        link = f"tg://proxy?server={quote(args.server)}&port={args.port}&secret={ee_secret}"
        print(f"{name}: {link}")


if __name__ == "__main__":
    main()
