#!/usr/bin/env python3
"""Correlate Suricata EVE alerts with an experiment interval and IP pair."""

import argparse
import errno
import hashlib
import ipaddress
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

MAX_EVE_FILE_BYTES = 256 * 1024 * 1024
MAX_EVE_LINE_BYTES = 1024 * 1024
MAX_EVE_RECORDS = 1_000_000
MAX_MATCHING_ALERTS = 10_000


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_json_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def valid_alert(event):
    alert = event.get("alert")
    if not isinstance(alert, dict):
        return False
    signature_id, signature, action = (alert.get("signature_id"),
                                       alert.get("signature"), alert.get("action"))
    return (type(signature_id) is int and signature_id > 0
            and isinstance(signature, str) and bool(signature)
            and (action is None or (isinstance(action, str) and bool(action))))


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timezone is required")
    return dt.astimezone(timezone.utc)


def correlate_eve(path, start, end, source, target):
    start = parse_time(start)
    end = parse_time(end)

    if end < start:
        raise ValueError("end precedes start")

    source = str(ipaddress.ip_address(source))
    target = str(ipaddress.ip_address(target))

    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError("EVE path must not be a symlink") from None
        raise
    try:
        info = os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_size > MAX_EVE_FILE_BYTES):
        os.close(fd)
        raise ValueError("EVE input must be a bounded single-link regular file")

    alerts = []
    malformed_lines = 0
    inspected_alerts = 0
    digest = hashlib.sha256()
    bytes_read = 0

    with os.fdopen(fd, "rb") as stream:
        remaining = info.st_size
        line_number = 0
        while remaining:
            raw = stream.readline(min(MAX_EVE_LINE_BYTES + 1, remaining))
            if not raw:
                break
            remaining -= len(raw)
            bytes_read += len(raw)
            digest.update(raw)
            line_number += 1
            if line_number > MAX_EVE_RECORDS:
                raise ValueError("EVE record count exceeds limit")
            if len(raw) > MAX_EVE_LINE_BYTES:
                raise ValueError("oversized EVE line")
            try:
                line = raw.decode("utf-8")
            except UnicodeError:
                malformed_lines += 1
                continue
            if not line.strip():
                continue
            try:
                event = json.loads(line, object_pairs_hook=unique_json_object,
                                   parse_constant=reject_json_constant)
            except (json.JSONDecodeError, ValueError):
                malformed_lines += 1
                continue
            if not isinstance(event, dict):
                malformed_lines += 1
                continue
            if event.get("event_type") != "alert":
                continue
            inspected_alerts += 1
            try:
                timestamp = parse_time(event["timestamp"])
                event_source = str(ipaddress.ip_address(event["src_ip"]))
                event_target = str(ipaddress.ip_address(event["dest_ip"]))
            except (KeyError, TypeError, ValueError):
                malformed_lines += 1
                continue
            if not valid_alert(event):
                malformed_lines += 1
                continue
            if not start <= timestamp <= end:
                continue
            if event_source != source or event_target != target:
                continue
            if len(alerts) >= MAX_MATCHING_ALERTS:
                raise ValueError("matching EVE alert count exceeds output limit")
            alert = event["alert"]
            alerts.append({
                "timestamp": timestamp.isoformat(),
                "src_ip": source,
                "dest_ip": target,
                "src_port": event.get("src_port"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
                "signature_id": alert["signature_id"],
                "signature": alert["signature"],
                "category": alert.get("category"),
                "severity": alert.get("severity"),
                "action": alert.get("action"),
                "line_number": line_number,
            })

    if bytes_read != info.st_size:
        raise ValueError("EVE file changed or was truncated during bounded read")

    return {
        "schema_version": 1,
        "source": "suricata_eve",
        "interval_start": start.isoformat(),
        "interval_end": end.isoformat(),
        "source_ip": source,
        "target_ip": target,
        "inspected_alerts": inspected_alerts,
        "matching_alerts": len(alerts),
        "malformed_records": malformed_lines,
        "input_bytes": bytes_read,
        "input_sha256": digest.hexdigest(),
        "alerts": alerts,
        "temporal_flow_match": bool(alerts),
        "causal_attribution": "unverified",
        "complete_log_coverage": "unverified",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve", type=Path, required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    try:
        result = correlate_eve(
            args.eve, args.start, args.end, args.source, args.target
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
