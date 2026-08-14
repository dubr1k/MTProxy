#!/usr/bin/env python3
"""Safely prepare or verify Mieru token metadata without reading token content.

The parent walk assumes root-owned, non-writable directories cannot be renamed by
an attacker while this process runs. The file itself remains FD-bound and is
identity-checked after mutation.
"""

from __future__ import annotations

import os
import stat
import sys
from typing import NoReturn

MIERU_GID = 10005
TOKEN_MODE = 0o440
MIN_TOKEN_BYTES = 32
MAX_TOKEN_BYTES = 513


class TokenError(Exception):
    pass


def fail(message: str) -> "NoReturn":
    print(f"prepare-mieru-token: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_path(path: str) -> None:
    if (
        not path.startswith("/")
        or path.startswith("//")
        or path == "/"
        or os.path.normpath(path) != path
    ):
        raise TokenError("token file must be a normalized absolute path")
    parent = os.path.dirname(path)
    components = parent.split("/")[1:]
    parents = ["/"]
    for component in components:
        parents.append(os.path.join(parents[-1], component))
    for current in parents:
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise TokenError(f"parent must be an existing non-symlink directory: {current}")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise TokenError(f"parent must be root-owned and not group/other-writable: {current}")


def validate_source(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise TokenError("token path must be an existing regular non-symlink file")
    if info.st_uid != 0:
        raise TokenError("token file must be owned by root")
    if info.st_nlink != 1:
        raise TokenError("token file must have exactly one link (hardlinks are forbidden)")
    if not MIN_TOKEN_BYTES <= info.st_size <= MAX_TOKEN_BYTES:
        raise TokenError("token file must be 32..513 bytes")


def prepare_or_verify(mode: str, path: str) -> None:
    validate_path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        validate_source(before)
        if mode == "prepare":
            os.fchown(fd, 0, MIERU_GID)
            os.fchmod(fd, TOKEN_MODE)
            os.fsync(fd)
        final = os.fstat(fd)
        validate_source(final)
        if (final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode)) != (
            0,
            MIERU_GID,
            TOKEN_MODE,
        ):
            raise TokenError("token file must have owner 0:10005 and mode 0440")
        path_info = os.lstat(path)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or stat.S_ISLNK(path_info.st_mode)
            or path_info.st_nlink != 1
            or (path_info.st_dev, path_info.st_ino) != (final.st_dev, final.st_ino)
        ):
            raise TokenError("token path identity changed during operation")
    finally:
        os.close(fd)


def main() -> None:
    if os.geteuid() != 0:
        fail("must run as root")
    if len(sys.argv) != 3 or sys.argv[1] not in {"prepare", "verify"}:
        fail(f"usage: {sys.argv[0]} prepare|verify absolute-token-file")
    mode, path = sys.argv[1:]
    try:
        prepare_or_verify(mode, path)
    except (OSError, TokenError) as exc:
        fail(str(exc))
    print(f"{'Prepared' if mode == 'prepare' else 'Verified'} Mieru manager token metadata: {path}")


if __name__ == "__main__":
    main()
