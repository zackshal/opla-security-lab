#!/usr/bin/env python3
"""Audit trail for blocked lab cleanup assessments; never performs cleanup.

This is not an authorization token. Uses exclusive flock and fsync for durable
JSONL append. Treat the registry itself as untrusted input.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("opla_cleanup_plan_v57", HERE / "opla-lab-cleanup-plan.py")
plan_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan_module)


def safe_directory(p, create=False):
    if p.is_symlink():
        raise ValueError("symlink in journal directory")
    if create:
        p.mkdir(mode=0o700, exist_ok=True)
    if not p.is_dir():
        raise ValueError("journal directory missing or invalid")
    mode = p.stat().st_mode
    if mode & 0o022:
        raise ValueError("journal directory must not be group/world writable")


def journal_path(root):
    root = Path(root)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("unsafe root")
    safe_directory(root)
    return root / "operations" / "lab-cleanup.jsonl"


def assess(root, lab):
    report = plan_module.plan(root, lab)
    return {"schema": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "lab": lab, "operation": "lab_cleanup_assessment", "outcome": "blocked",
            "execution_allowed": False, "reasons": report["reasons"],
            "audit_summary": report["audit_summary"]}


def append_record(root, lab):
    path = journal_path(root)
    record = assess(root, lab)
    safe_directory(path.parent, create=True)
    if path.is_symlink():
        raise ValueError("journal file is symlink")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "ab", closefd=False) as fh:
            fcntl.flock(fd, fcntl.LOCK_EX)
            mode = os.fstat(fd)
            if not stat.S_ISREG(mode.st_mode) or mode.st_nlink != 1 or (mode.st_mode & 0o077):
                raise ValueError("unsafe journal file permissions or type")
            fh.write((json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
            fh.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    return record


def read_records(root):
    path = journal_path(root)
    if path.is_symlink():
        raise ValueError("journal file is symlink")
    if not path.exists():
        return []
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ValueError("invalid journal")
        data = os.read(fd, 8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError("journal too large for inspection")
        return [json.loads(x) for x in data.decode("utf-8").splitlines() if x.strip()]
    finally:
        os.close(fd)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("record", "list"))
    p.add_argument("--root", default="/var/lib/opla")
    p.add_argument("--lab")
    args = p.parse_args(argv)
    if args.command == "record":
        if not args.lab:
            p.error("--lab required")
        print(json.dumps(append_record(args.root, args.lab), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(read_records(args.root), ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print("OPLA cleanup journal:", e, file=sys.stderr)
        sys.exit(2)
