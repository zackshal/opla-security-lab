#!/usr/bin/env python3
"""Correlate Suricata EVE alerts with an experiment interval and IP pair."""

import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


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
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or unsafe EVE file")

    alerts = []
    malformed_lines = 0
    inspected_alerts = 0

    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if len(line) > 1024 * 1024:
                raise ValueError("oversized EVE line")

            if not line.strip():
                continue

            try:
                event = json.loads(line)
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
            except (KeyError, TypeError, ValueError):
                malformed_lines += 1
                continue

            if not start <= timestamp <= end:
                continue

            if event.get("src_ip") != source or event.get("dest_ip") != target:
                continue

            alert = event.get("alert")
            if not isinstance(alert, dict):
                malformed_lines += 1
                continue

            alerts.append({
                "timestamp": timestamp.isoformat(),
                "src_ip": source,
                "dest_ip": target,
                "src_port": event.get("src_port"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
                "signature_id": alert.get("signature_id"),
                "signature": alert.get("signature"),
                "category": alert.get("category"),
                "severity": alert.get("severity"),
                "action": alert.get("action"),
                "line_number": line_number,
            })

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
