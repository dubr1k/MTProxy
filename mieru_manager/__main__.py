from __future__ import annotations

import os
from pathlib import Path

from .server import ManagerHTTPServer
from .service import MieruManager, MitaCLI


def main() -> None:
    token = (
        Path(os.getenv("MIERU_MANAGER_TOKEN_FILE", "/etc/mieru-manager/token"))
        .read_text()
        .strip()
    )
    manager = MieruManager(
        mita=MitaCLI(
            executable="/usr/bin/mita",
            expected_sha256=os.environ["MIERU_MITA_SHA256"],
        ),
        state_dir=Path(os.getenv("MIERU_MANAGER_STATE", "/var/lib/mieru-manager")),
        public_host=os.environ["MIERU_PUBLIC_HOST"],
    )
    manager.bootstrap()
    server = ManagerHTTPServer(
        Path(os.getenv("MIERU_MANAGER_SOCKET", "/run/mieru-manager/manager.sock")),
        manager,
        token,
        socket_uid=int(os.environ["MIERU_PANEL_UID"])
        if os.getenv("MIERU_PANEL_UID")
        else None,
        socket_mode=int(os.getenv("MIERU_SOCKET_MODE", "660"), 8),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
