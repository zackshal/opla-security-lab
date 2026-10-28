#!/usr/bin/env python3
"""Verify inherited OPLA creation lock descriptors."""

import errno
import fcntl
import os
import stat
import sys
from pathlib import Path


ROOT = Path("/var/lib/opla")


def verify_fd(fd, path, expected_uid=0):
    inherited = os.fstat(fd)

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    probe_fd = os.open(path, flags)

    try:
        current = os.fstat(probe_fd)

        if (inherited.st_dev, inherited.st_ino) != (
            current.st_dev, current.st_ino
        ):
            raise RuntimeError("inherited lock identity mismatch")

        if not stat.S_ISREG(inherited.st_mode):
            raise RuntimeError("lock is not a regular file")

        if inherited.st_uid != expected_uid or inherited.st_nlink != 1:
            raise RuntimeError("unsafe lock ownership or link count")

        if inherited.st_mode & 0o022:
            raise RuntimeError("unsafe lock permissions")

        # An independent open-file description must not be able
        # to obtain the lock while the launcher is holding it.
        try:
            fcntl.flock(
                probe_fd,
                fcntl.LOCK_EX | fcntl.LOCK_NB
            )
        except OSError as exc:
            if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise
        else:
            fcntl.flock(probe_fd, fcntl.LOCK_UN)
            raise RuntimeError("expected lifecycle lock is not held")

    finally:
        os.close(probe_fd)


def verify_pair(root, global_fd, create_fd, expected_uid=0):
    if global_fd == create_fd:
        raise RuntimeError("creation lock descriptors must differ")

    verify_fd(global_fd, root / ".opla-prune.lock", expected_uid)
    verify_fd(create_fd, root / "create.lock", expected_uid)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("root required")

    global_fd = int(os.environ["OPLA_CREATE_GLOBAL_FD"])
    create_fd = int(os.environ["OPLA_CREATE_LOCAL_FD"])

    if global_fd < 3 or create_fd < 3:
        raise RuntimeError("invalid inherited descriptor")

    verify_pair(ROOT, global_fd, create_fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"BLOCKED: creation lock verification: {exc}",
              file=sys.stderr)
        sys.exit(2)
