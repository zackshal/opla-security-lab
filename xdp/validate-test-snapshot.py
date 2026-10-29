#!/usr/bin/env python3
"""Require a live OPLA XDP attachment before accepting a traffic test sample."""
import json
import sys


def validate(raw):
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("collector returned malformed JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("collector snapshot must be a JSON object")
    if type(data.get("loaded")) is not int or data["loaded"] != 1:
        raise ValueError("XDP is not attached; refusing to generate test traffic")
    if data.get("mode") not in {"native", "generic"}:
        raise ValueError("XDP attachment mode is unavailable or unsupported")
    return data


def main():
    try:
        validate(sys.stdin.read())
    except ValueError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
