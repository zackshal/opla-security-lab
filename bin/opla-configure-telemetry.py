#!/usr/bin/env python3
"""Fail lab configuration unless every expected guest telemetry source responds."""
import json
import sys


def validate_snapshot(data):
    if not isinstance(data, dict):
        raise ValueError("telemetry snapshot must be a JSON object")

    required_numeric = (
        "loaded", "http_available", "http_up", "http_status",
        "scan_enabled", "scan_up", "ids_enabled", "ids_up",
    )
    for key in required_numeric:
        if type(data.get(key)) is not int:
            raise ValueError(f"telemetry field {key} is missing or invalid")

    expected = {
        "loaded": 1,
        "http_available": 1,
        "http_up": 1,
        "http_status": 200,
        "scan_enabled": 1,
        "scan_up": 1,
        "ids_enabled": 1,
        "ids_up": 1,
    }
    failed = [key for key, value in expected.items() if data[key] != value]
    if failed:
        raise ValueError("telemetry sources unavailable or unhealthy: " + ", ".join(failed))

    if data.get("mode") not in {"native", "generic"}:
        raise ValueError("XDP attachment mode is missing or unsupported")
    if not isinstance(data.get("scan_details"), str) or data["scan_details"] == "Detector unavailable or disabled":
        raise ValueError("passive scan detector has no current status")
    return {
        "status": "ready",
        "xdp_mode": data["mode"],
        "http_status": data["http_status"],
        "scan_detector": "running",
        "suricata": "running",
    }


def main():
    try:
        result = validate_snapshot(json.load(sys.stdin))
    except (OSError, ValueError, TypeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
