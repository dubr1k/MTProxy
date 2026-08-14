#!/usr/bin/env python3
"""Validate and FD-stage the immutable Compose Mieru token secret."""

from __future__ import annotations

import os
import stat
import sys

SOURCE_UID = 0
SOURCE_GID = 10005
SOURCE_MODE = 0o440
TARGET_UID = 10001
TARGET_GID = 101
TARGET_MODE = 0o400
MIN_BYTES = 32
MAX_BYTES = 513


class StageError(Exception):
    pass


def validate_source(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise StageError("Mieru token source must be a regular non-symlink file")
    if info.st_nlink != 1:
        raise StageError("Mieru token source must have exactly one link")
    if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
        SOURCE_UID,
        SOURCE_GID,
        SOURCE_MODE,
    ):
        raise StageError("Mieru token source must have owner 0:10005 and mode 0440")
    if not MIN_BYTES <= info.st_size <= MAX_BYTES:
        raise StageError("Mieru token source must be 32..513 bytes")


def open_source(path: str) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        validate_source(os.fstat(fd))
    except Exception:
        os.close(fd)
        raise
    return fd


def verify(path: str) -> None:
    fd = open_source(path)
    os.close(fd)


def stage(source: str, destination: str) -> None:
    source_fd = open_source(source)
    destination_fd: int | None = None
    destination_identity: tuple[int, int] | None = None
    try:
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            TARGET_MODE,
        )
        created = os.fstat(destination_fd)
        destination_identity = (created.st_dev, created.st_ino)
        total = 0
        while True:
            chunk = os.read(source_fd, min(65536, MAX_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise StageError("Mieru token source changed during staging")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        source_final = os.fstat(source_fd)
        validate_source(source_final)
        if total != source_final.st_size:
            raise StageError("Mieru token source changed during staging")
        os.fchown(destination_fd, TARGET_UID, TARGET_GID)
        os.fchmod(destination_fd, TARGET_MODE)
        os.fsync(destination_fd)
        final = os.fstat(destination_fd)
        path_info = os.lstat(destination)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or (final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode), final.st_size)
            != (TARGET_UID, TARGET_GID, TARGET_MODE, total)
            or (path_info.st_dev, path_info.st_ino) != (final.st_dev, final.st_ino)
            or not stat.S_ISREG(path_info.st_mode)
            or path_info.st_nlink != 1
        ):
            raise StageError("staged Mieru token failed final identity or metadata check")
    except Exception:
        if destination_identity is not None:
            try:
                current = os.lstat(destination)
                if (current.st_dev, current.st_ino) == destination_identity:
                    os.unlink(destination)
            except FileNotFoundError:
                pass
        raise
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)


def main() -> None:
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "verify":
            verify(sys.argv[2])
        elif len(sys.argv) == 4 and sys.argv[1] == "stage":
            stage(sys.argv[2], sys.argv[3])
        else:
            raise StageError(f"usage: {sys.argv[0]} verify SOURCE | stage SOURCE DESTINATION")
    except (OSError, StageError) as exc:
        print(f"stage-secret: {exc}", file=sys.stderr)
        raise SystemExit(64) from None


if __name__ == "__main__":
    main()
