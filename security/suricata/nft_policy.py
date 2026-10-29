#!/usr/bin/env python3
"""Fail-closed ownership checks for the guest-local Suricata nft table."""

import json
import fcntl
import os
from pathlib import Path
import stat
import subprocess
from contextlib import contextmanager

TABLE = "opla_ips"
OWNER_COMMENT = "opla-suricata-managed-v1"
LOCK_PATH = Path("/run/lock/opla-suricata-nft.lock")


@contextmanager
def exclusive_lock(path):
    """Serialize cooperating OPLA operations with a validated lock file."""
    path = Path(path)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or (parent.st_mode & 0o022 and not (os.geteuid() == 0 and parent.st_mode & stat.S_ISVTX))):
        raise RuntimeError("Suricata nft lock directory is not trusted")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise RuntimeError("Suricata nft lock file is unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate nft JSON key")
        result[key] = value
    return result


def table_status(runner=subprocess.run):
    """Return ABSENT/OWNED; unknown or unmarked same-name tables block."""
    result = runner(["nft", "-j", "list", "table", "inet", TABLE],
                    capture_output=True, text=True)
    if result.returncode:
        if "No such file or directory" in (result.stderr or ""):
            return "ABSENT"
        raise RuntimeError("cannot establish OPLA nft table state")
    try:
        payload = json.loads(result.stdout, object_pairs_hook=_unique_object)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("nft table inspection returned invalid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("nftables"), list):
        raise RuntimeError("nft table inspection has an invalid structure")
    tables = [entry["table"] for entry in payload["nftables"]
              if isinstance(entry, dict) and isinstance(entry.get("table"), dict)]
    matches = [item for item in tables
               if item.get("family") == "inet" and item.get("name") == TABLE]
    if len(matches) != 1:
        raise RuntimeError("nft inspection did not identify exactly one target table")
    if matches[0].get("comment") != OWNER_COMMENT:
        return "FOREIGN"
    return "OWNED"


def delete_owned_table(runner=subprocess.run, *, lock_path=LOCK_PATH):
    """Delete only a table carrying the explicit OPLA ownership marker."""
    with exclusive_lock(lock_path):
        status = table_status(runner)
        if status == "ABSENT":
            return False
        if status != "OWNED":
            raise RuntimeError("nft table inet opla_ips is unmarked; manual review required")
        runner(["nft", "delete", "table", "inet", TABLE], check=True)
        return True


def replace_table(rules, runner=subprocess.run, *, lock_path=LOCK_PATH):
    """Check and transactionally replace only an absent or marked OPLA table."""
    with exclusive_lock(lock_path):
        status = table_status(runner)
        if status == "FOREIGN":
            raise RuntimeError("nft table inet opla_ips is unmarked; manual review required")
        candidate = ("delete table inet opla_ips\n" if status == "OWNED" else "") + rules
        runner(["nft", "--check", "-f", "-"], input=candidate, text=True, check=True)
        # Reinspect after validation so other OPLA callers cannot race apply.
        current = table_status(runner)
        if current == "FOREIGN":
            raise RuntimeError("nft table inet opla_ips changed to unmarked policy")
        if current != status:
            candidate = ("delete table inet opla_ips\n" if current == "OWNED" else "") + rules
            runner(["nft", "--check", "-f", "-"], input=candidate, text=True, check=True)
            if table_status(runner) != current:
                raise RuntimeError("nft table inet opla_ips changed during policy validation")
        runner(["nft", "-f", "-"], input=candidate, text=True, check=True)
