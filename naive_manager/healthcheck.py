from __future__ import annotations

import os
import socket
from pathlib import Path


def main() -> None:
    token = Path(os.getenv("NAIVE_MANAGER_TOKEN_FILE", "/run/secrets/naive-manager-token")).read_text().strip()
    path = os.getenv("NAIVE_MANAGER_SOCKET", "/run/naive-manager/manager.sock")
    request = f"GET /v1/health HTTP/1.1\r\nHost: manager\r\nX-Naive-Token: {token}\r\nConnection: close\r\n\r\n".encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(path)
        client.sendall(request)
        status = client.recv(64).split(b"\r\n", 1)[0]
    if status != b"HTTP/1.0 200 OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
