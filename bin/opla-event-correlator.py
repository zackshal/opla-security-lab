#!/usr/bin/env python3
"""Offline correlation of OPLA security telemetry snapshots."""

import argparse
import json
import sys
from pathlib import Path

METRICS = {
    "xdp": ("syn", "pass", "drop", "xdp_scan_events", "xdp_scan_drop"),
    "scan_detector": ("scan_alerts", "scan_capture_drops"),
    "suricata": ("ids_alerts", "ids_blocked", "ids_parse_errors"),
}


def delta(before, after, key):
    a, b = before.get(key), after.get(key)

    if a is None or b is None:
        return None

    if type(a) is not int or type(b) is not int:
        raise ValueError(f"Invalid counter: {key}")

    if a < 0 or b < a:
        raise ValueError(f"Counter reset: {key}")

    return b - a



def availability(before, after, flags):
    values = [snapshot.get(key) for snapshot in (before, after) for key in flags]
    if any(type(value) is not int or value not in (0, 1) for value in values):
        return "unknown"
    return "available" if all(value == 1 for value in values) else "unavailable"


def observed_if_available(value, state):
    return (value > 0) if state == "available" and value is not None else None


def correlate(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Snapshots must be JSON objects")

    metrics = {
        group: {
            key: delta(before, after, key)
            for key in keys
        }
        for group, keys in METRICS.items()
    }

    xdp = metrics["xdp"]
    scan = metrics["scan_detector"]
    ids = metrics["suricata"]

    availability_status = {
        "xdp": availability(before, after, ("loaded",)),
        "scan_detector": availability(
            before, after, ("scan_enabled", "scan_up")
        ),
        "suricata": availability(
            before, after, ("ids_enabled", "ids_up")
        ),
    }

    return {
        "schema_version": 1,
        "mode": "offline_correlation",
        "metrics": metrics,
        "availability": availability_status,
        "observations": {
            "syn_traffic_observed": observed_if_available(
                xdp["syn"], availability_status["xdp"]
            ),
            "xdp_packets_dropped": observed_if_available(
                xdp["drop"], availability_status["xdp"]
            ),
            "xdp_scan_events": observed_if_available(
                xdp["xdp_scan_events"], availability_status["xdp"]
            ),
            "scan_detector_alerts": observed_if_available(
                scan["scan_alerts"], availability_status["scan_detector"]
            ),
            "suricata_alerts": observed_if_available(
                ids["ids_alerts"], availability_status["suricata"]
            ),
        },
        "attack_attribution": "unverified",
        "limitations": [
            "Counters are cumulative and do not identify a specific flow.",
            "Unavailable or unknown sources cannot prove absence of alerts.",
            "XDP scan support must be verified separately.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args()

    try:
        if args.before.is_symlink() or args.after.is_symlink():
            raise ValueError("Snapshot symlinks are not allowed")

        before = json.loads(args.before.read_text(encoding="utf-8"))
        after = json.loads(args.after.read_text(encoding="utf-8"))

        report = correlate(before, after)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    except (OSError, ValueError, TypeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
