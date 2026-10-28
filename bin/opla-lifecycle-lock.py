#!/usr/bin/env python3
"""Safe lifecycle lock acquisition for OPLA."""

import contextlib
import fcntl
import os
import stat
from pathlib import Path


class UnsafeLock(RuntimeError):
    pass


def validate(fd):
    st = os.fstat(fd)

    if not stat.S_ISREG(st.st_mode):
        raise UnsafeLock("lock must be a regular file")

    if st.st_uid != 0:
        raise UnsafeLock("lock must be owned by root")

    if st.st_nlink != 1:
        raise UnsafeLock("lock must have exactly one hard link")

    if st.st_mode & 0o022:
        raise UnsafeLock("lock must not be group/world writable")

    return st


def open_lock(path):
    """Open without following symlinks or truncating existing files."""
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)

    try:
        validate(fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        validate(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def lifecycle_lock(path):
    fd = open_lock(Path(path))
    try:
        yield fd
    finally:
        os.close(fd)
