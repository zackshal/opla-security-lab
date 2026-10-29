#!/usr/bin/env python3
"""Safely migrate a legacy Compose secret into per-user OPLA config."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys

MAX_ENV_BYTES = 64 * 1024
DB_PASSWORD_LINE = re.compile(r"^\s*DB_PASSWORD\s*=\s*(.*?)\s*$")


def _read_env(path: Path, owner_uid: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid not in {0, owner_uid} or info.st_mode & 0o022
                or info.st_size > MAX_ENV_BYTES):
            raise ValueError("legacy monitoring env has unsafe file identity")
        chunks = []
        remaining = MAX_ENV_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if len(raw) > MAX_ENV_BYTES:
        raise ValueError("legacy monitoring env exceeds size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("legacy monitoring env is not UTF-8") from None
    if "\x00" in text:
        raise ValueError("legacy monitoring env contains NUL")
    passwords = []
    for line in text.splitlines():
        match = DB_PASSWORD_LINE.match(line)
        if match:
            value = match.group(1)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            passwords.append(value)
    if len(passwords) != 1 or not passwords[0]:
        raise ValueError("legacy monitoring env must contain exactly one non-empty DB_PASSWORD")
    return raw


def _ensure_private_parent(home: Path, parent: Path, owner_uid: int, owner_gid: int) -> None:
    home = home.absolute()
    parent = parent.absolute()
    try:
        parent.relative_to(home)
    except ValueError:
        raise ValueError("monitoring config path must be under the invoking user's home") from None
    if home.is_symlink() or not home.is_dir() or home.stat().st_uid != owner_uid:
        raise ValueError("invoking user's home directory has unsafe identity")
    current = home
    relative = parent.relative_to(home)
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            if os.geteuid() == 0 and owner_uid != 0:
                os.chown(current, owner_uid, owner_gid)
            info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid
                or info.st_mode & 0o022):
            raise ValueError("monitoring config directory has unsafe identity or permissions")


def _validate_destination(path: Path, owner_uid: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > MAX_ENV_BYTES):
            raise ValueError("monitoring env destination must be a private mode-0600 regular file")
    finally:
        os.close(fd)


def migrate(source, destination, *, owner_uid: int, owner_gid: int, home) -> bool:
    """Copy a private legacy env once. Existing destinations are never replaced."""
    source, destination, home = Path(source), Path(destination), Path(home)
    if destination.exists() or destination.is_symlink():
        _validate_destination(destination, owner_uid)
        return False
    if source.is_symlink():
        raise ValueError("legacy monitoring env must not be a symlink")
    if not source.exists():
        return False
    raw = _read_env(source, owner_uid)
    _ensure_private_parent(home, destination.parent, owner_uid, owner_gid)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    try:
        if os.geteuid() == 0 and owner_uid != 0:
            os.fchown(fd, owner_uid, owner_gid)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while migrating monitoring env")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    _validate_destination(destination, owner_uid)
    directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--owner-uid", required=True, type=int)
    parser.add_argument("--owner-gid", required=True, type=int)
    parser.add_argument("--home", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        copied = migrate(args.source, args.destination, owner_uid=args.owner_uid,
                         owner_gid=args.owner_gid, home=args.home)
    except (OSError, ValueError) as exc:
        print(f"BLOCKED: monitoring secret migration failed: {exc}", file=sys.stderr)
        return 2
    if copied:
        print(f"Migrated existing monitoring secret to {args.destination} (mode 0600).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
