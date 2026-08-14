from __future__ import annotations

import argparse
import sys

from .app import Settings
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="MTProxy panel administration")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin", help="create the initial administrator")
    create.add_argument("--username", required=True)
    create.add_argument("--role", choices=("owner", "admin", "viewer"), default="owner")
    create.add_argument("--password-stdin", action="store_true", required=True)
    args = parser.parse_args()
    if args.command == "create-admin":
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            parser.error("password is required on stdin")
        Store(Settings().database_path).create_admin(args.username, password, args.role)
        print(f"Administrator {args.username!r} created.")


if __name__ == "__main__":
    main()
