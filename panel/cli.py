from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent_transport import CertificateAuthority
from .app import Settings
from .fleet import FleetStore
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="MTProxy panel administration")
    parser.add_argument("--database", type=Path, default=None, help="override PANEL_DATABASE")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin", help="create the initial administrator")
    create.add_argument("--username", required=True)
    create.add_argument("--role", choices=("owner", "admin", "viewer"), default="owner")
    create.add_argument("--password-stdin", action="store_true", required=True)

    register = sub.add_parser("fleet-register-node", help="create an unenrolled fleet node")
    register.add_argument("node_id")
    register.add_argument("--display-name", required=True)
    ca_init = sub.add_parser("fleet-ca-init", help="initialize the offline client certificate CA")
    ca_init.add_argument("--ca-dir", type=Path, required=True)
    ca_init.add_argument("--common-name", default="MTProxy fleet client CA")
    sign = sub.add_parser("fleet-sign-csr", help="sign a node-generated CSR and bind its certificate")
    sign.add_argument("node_id")
    sign.add_argument("--ca-dir", type=Path, required=True)
    sign.add_argument("--csr", type=Path, required=True)
    sign.add_argument("--out", type=Path, required=True)
    sign.add_argument("--days", type=int, default=90)
    bind = sub.add_parser("fleet-bind-cert", help="authorize an already-issued node certificate")
    bind.add_argument("node_id")
    bind.add_argument("--cert", type=Path, required=True)
    revoke = sub.add_parser("fleet-revoke-cert", help="immediately reject a node certificate serial")
    revoke.add_argument("node_id")
    revoke.add_argument("--serial", required=True)

    args = parser.parse_args()
    database = args.database or Settings().database_path
    if args.command == "create-admin":
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            parser.error("password is required on stdin")
        Store(database).create_admin(args.username, password, args.role)
        print(f"Administrator {args.username!r} created.")
    elif args.command == "fleet-register-node":
        print(json.dumps(FleetStore(database).register_node(args.node_id, args.display_name, {}), sort_keys=True))
    elif args.command == "fleet-ca-init":
        CertificateAuthority(args.ca_dir).initialize(args.common_name)
        print(f"Client CA initialized at {args.ca_dir}; keep ca.key offline/root-only.")
    elif args.command == "fleet-sign-csr":
        if not 1 <= args.days <= 397:
            parser.error("--days must be between 1 and 397")
        metadata = CertificateAuthority(args.ca_dir).sign_node_csr(args.node_id, args.csr, args.out, args.days)
        print(json.dumps(metadata, sort_keys=True))
    elif args.command == "fleet-bind-cert":
        metadata = CertificateAuthority.certificate_metadata(args.cert)
        FleetStore(database).bind_certificate(args.node_id, metadata)
        print(json.dumps(metadata, sort_keys=True))
    elif args.command == "fleet-revoke-cert":
        FleetStore(database).revoke_certificate(args.node_id, args.serial)
        print(f"Certificate {args.serial.upper()} revoked for {args.node_id}.")


if __name__ == "__main__":
    main()
