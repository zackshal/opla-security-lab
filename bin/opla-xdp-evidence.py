#!/usr/bin/env python3
"""Analyze real XDP counter snapshots."""

import json
from pathlib import Path

COUNTERS = ("syn", "pass", "drop", "map_full", "fragment_drop")


def analyze(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("invalid XDP snapshots")

    if type(before.get("loaded")) is not int or before["loaded"] != 1:
        raise ValueError("XDP not loaded before experiment")

    if type(after.get("loaded")) is not int or after["loaded"] != 1:
        raise ValueError("XDP not loaded after experiment")

    deltas = {}

    for name in COUNTERS:
        old = before.get(name)
        new = after.get(name)

        if type(old) is not int or type(new) is not int:
            raise ValueError(f"invalid counter: {name}")

        if old < 0 or new < old:
            raise ValueError(f"counter reset or invalid: {name}")

        deltas[name] = new - old

    return {
        "source": "xdp_counter_snapshots",
        "telemetry_collected": True,
        "counters_valid": True,
        "deltas": deltas,
        "syn_packets_observed": deltas["syn"] > 0,
        "packets_dropped": deltas["drop"] > 0,
        "scan_detected": None,
        "note": (
            "Counters confirm packet processing, not necessarily "
            "a scan-detection event. Other traffic may affect counters."
        ),
    }


def analyze_files(before_path, after_path):
    before = json.loads(Path(before_path).read_text(encoding="utf-8"))
    after = json.loads(Path(after_path).read_text(encoding="utf-8"))
    return analyze(before, after)
