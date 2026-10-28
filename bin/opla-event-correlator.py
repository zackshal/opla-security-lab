#!/usr/bin/env python3
"""Offline correlation of OPLA security telemetry snapshots."""

import argparse
import ipaddress
import json
import math
import re
import sys
from pathlib import Path

METRICS = {
    "xdp": ("syn", "pass", "drop", "xdp_scan_events", "xdp_scan_drop"),
    "scan_detector": ("scan_alerts", "scan_capture_drops"),
    "suricata": ("ids_alerts", "ids_blocked", "ids_parse_errors"),
}

MAX_CLIENT_SAMPLES = 10000


def client_continuity(interval, probes, *, parse_time, max_gap_seconds=2):
    """Verify bounded sampled coverage; never infer uninterrupted availability.

    parse_time is the existing UTC-aware EVE timestamp parser supplied by the
    reporter. Expected client identity belongs to the interval produced from
    lab state; interval.source_ip remains the attacker and is never the client.
    The artifact cannot select its own acceptance cadence.
    """
    if (type(max_gap_seconds) not in (int, float)
            or not math.isfinite(max_gap_seconds) or max_gap_seconds <= 0):
        raise ValueError("client maximum sampling gap must be finite and positive")
    if not isinstance(interval, dict) or not isinstance(probes, dict):
        raise ValueError("client interval and evidence must be objects")
    for record in (interval, probes):
        if type(record.get("schema_version")) is not int or record["schema_version"] != 1:
            raise ValueError("unsupported client evidence schema")
    lab = interval.get("lab_id")
    experiment = interval.get("experiment")
    if (not isinstance(lab, str) or re.fullmatch(r"lab-[A-Za-z0-9]{4,32}", lab) is None
            or not isinstance(experiment, str)
            or re.fullmatch(r"scenario-[A-Za-z0-9][A-Za-z0-9-]{0,127}", experiment) is None):
        raise ValueError("independently recorded lab/experiment identity required")
    if probes.get("lab_id") != lab or probes.get("experiment") != experiment:
        raise ValueError("client lab or experiment identity mismatch")
    if interval.get("clock_source") != "victim" or probes.get("clock_source") != "victim":
        raise ValueError("client samples require the experiment victim clock domain")
    if probes.get("source_role") != "client" or probes.get("target_role") != "victim":
        raise ValueError("independent client-to-victim observations required")
    client = str(ipaddress.ip_address(interval["client_ip"]))
    target = str(ipaddress.ip_address(interval["target_ip"]))
    attacker = str(ipaddress.ip_address(interval["source_ip"]))
    if client in (target, attacker):
        raise ValueError("client must differ from victim and attacker")
    if (str(ipaddress.ip_address(probes.get("source_ip"))) != client
            or str(ipaddress.ip_address(probes.get("target_ip"))) != target):
        raise ValueError("client source or target address mismatch")
    start, end = parse_time(interval["start"]), parse_time(interval["end"])
    if end <= start:
        raise ValueError("client interval must have positive duration")
    samples = probes.get("samples")
    if not isinstance(samples, list) or not 2 <= len(samples) <= MAX_CLIENT_SAMPLES:
        raise ValueError("client evidence requires a bounded series of at least two samples")
    times = []
    unsuccessful = 0
    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError("invalid client sample")
        timestamp = parse_time(sample.get("timestamp"))
        if times and timestamp <= times[-1]:
            raise ValueError("client timestamps must be strictly increasing")
        if type(sample.get("returncode")) is not int or type(sample.get("http_status")) is not int:
            raise ValueError("client return code and HTTP status must be integers")
        if sample["returncode"] != 0 or sample["http_status"] != 200:
            unsuccessful += 1
        times.append(timestamp)
    observed_gap = max((right - left).total_seconds() for left, right in zip(times, times[1:]))
    inside = sum(start <= timestamp <= end for timestamp in times)
    reasons = []
    if times[0] > start or times[-1] < end:
        reasons.append("interval_boundaries_not_covered")
    if inside < 2:
        reasons.append("insufficient_samples_within_interval")
    if observed_gap > max_gap_seconds:
        reasons.append("sampling_gap_exceeds_limit")
    if unsuccessful:
        reasons.append("unsuccessful_client_probe")
    covered = not reasons
    return {
        "status": "covered_at_cadence" if covered else "insufficient_coverage",
        "covered_at_cadence": covered,
        "continuous_availability_verified": False,
        "lab_id": lab, "experiment": experiment, "clock_source": "victim",
        "client_ip": client, "target_ip": target,
        "interval_start": start.isoformat(), "interval_end": end.isoformat(),
        "sample_count": len(times), "interval_sample_count": inside,
        "maximum_gap_seconds": max_gap_seconds, "observed_maximum_gap_seconds": observed_gap,
        "unsuccessful_samples": unsuccessful, "reasons": reasons,
        "provenance": "unverified",
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
