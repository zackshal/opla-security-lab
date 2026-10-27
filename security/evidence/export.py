#!/usr/bin/env python3
"""Bounded read-only export of OPLA security event logs."""

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

SOURCES = {
    "suricata": Path("/var/log/opla-suricata/eve.json"),
    "scan": Path("/var/log/opla-scan/events.jsonl"),
}
MAX_BYTES = 1024 * 1024


def export(kind, paths=None, limit=MAX_BYTES):
    sources = SOURCES if paths is None else paths
    if kind not in sources:
        raise ValueError("unsupported evidence source")
    if not 1 <= limit <= MAX_BYTES:
        raise ValueError("invalid export limit")

    path = Path(sources[kind])

    try:
        with path.open("rb") as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("not a regular file")
            if path.is_symlink():
                raise ValueError("symlink source rejected")

            size = st.st_size
            offset = max(0, size - limit)
            stream.seek(offset)
            data = stream.read(limit)

    except FileNotFoundError:
        return {
            "source": kind,
            "status": "unavailable",
            "reason": "log not found",
            "records": [],
            "coverage": "unavailable",
        }

    # If the capture starts mid-file, discard the partial first line.
    truncated = offset > 0
    if truncated:
        boundary = data.find(b"\n")
        data = data[boundary + 1:] if boundary >= 0 else b""

    # Keep only complete JSONL records.
    last_newline = data.rfind(b"\n")
    data = data[:last_newline + 1] if last_newline >= 0 else b""

    valid = []
    malformed = 0

    for raw in data.splitlines():
        try:
            record = json.loads(raw)
            if not isinstance(record, dict):
                raise ValueError("not an object")
            valid.append(record)
        except (ValueError, UnicodeDecodeError):
            malformed += 1

    return {
        "source": kind,
        "status": "captured",
        "file_size_bytes": size,
        "read_offset": offset,
        "truncated": truncated,
        "coverage": "partial" if truncated else "unverified",
        "sha256_captured_region": hashlib.sha256(data).hexdigest(),
        "malformed_records": malformed,
        "records": valid,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=tuple(SOURCES), required=True)
    args = parser.parse_args()

    try:
        print(json.dumps(export(args.kind), ensure_ascii=False))
        return 0
    except (OSError, ValueError) as exc:
        print(f"evidence export failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
