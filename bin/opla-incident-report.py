#!/usr/bin/env python3
"""Offline incident report from OPLA experiment evidence."""

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


eve = load_module("opla_incident_eve", "opla-eve-correlator.py")
counters = load_module("opla_incident_counters", "opla-event-correlator.py")

MAX_CLIENT_EVIDENCE_BYTES = 1024 * 1024


def client_continuity_report(experiment, interval, *, max_gap_seconds=2):
    """Read only the optional bounded regular artifact; preserve uncertainty."""
    unavailable = {"status": "unavailable", "covered_at_cadence": False,
                   "continuous_availability_verified": False}
    directory_fd = None
    descriptor = None
    evidence_hash = None
    try:
        if not isinstance(interval, dict):
            raise ValueError("client interval must be an object")
        directory_fd = os.open(experiment, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open("client-probes.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory_fd)
        except FileNotFoundError:
            return {**unavailable, "reason": "client-probes.json not supplied"}
        file_stat = os.fstat(descriptor)
        if (not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1
                or file_stat.st_size > MAX_CLIENT_EVIDENCE_BYTES):
            raise ValueError("unsafe or oversized client evidence")
        data = bytearray()
        while len(data) <= MAX_CLIENT_EVIDENCE_BYTES:
            block = os.read(descriptor, min(65536, MAX_CLIENT_EVIDENCE_BYTES + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) > MAX_CLIENT_EVIDENCE_BYTES:
            raise ValueError("client evidence exceeds byte limit")
        evidence_hash = hashlib.sha256(data).hexdigest()
        if interval.get("experiment") != Path(experiment).name:
            raise ValueError("client interval experiment differs from artifact directory")
        return {**counters.client_continuity(interval, json.loads(data.decode("utf-8")),
                                             parse_time=eve.parse_time, max_gap_seconds=max_gap_seconds),
                "artifact_sha256": evidence_hash}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError) as exc:
        return {**unavailable, "status": "invalid", "artifact_sha256": evidence_hash,
                "reason": f"{type(exc).__name__}: {str(exc)[:300]}"}
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def read_json(path):
    path = Path(path)
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"missing or unsafe file: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
        raise ValueError(f"missing or unsafe file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def scan_events(path, start, end, source, target):
    """Filter detector JSONL by UTC second and source/target IP pair."""
    path = Path(path)
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise ValueError("missing or unsafe scan events file") from exc
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
        raise ValueError("missing or unsafe scan events file")

    # The detector records integer Unix seconds, not subsecond timestamps.
    first = int(eve.parse_time(start).timestamp())
    last = int(eve.parse_time(end).timestamp())
    source = str(ipaddress.ip_address(source))
    target = str(ipaddress.ip_address(target))

    if last < first:
        raise ValueError("invalid interval")

    matched = []
    malformed = 0

    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if len(line) > 1024 * 1024:
                raise ValueError("oversized scan event line")
            if not line.strip():
                continue

            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("invalid JSON object")

                ts = event["timestamp"]
                if type(ts) is not int:
                    raise ValueError("invalid timestamp")

                if not first <= ts <= last:
                    continue

                if (
                    event.get("source_ip") != source
                    or event.get("destination_ip") != target
                    or event.get("event") != "tcp_port_scan_suspected"
                ):
                    continue

                matched.append({
                    "timestamp": datetime.fromtimestamp(
                        ts, timezone.utc
                    ).isoformat(),
                    "event": event["event"],
                    "source_ip": source,
                    "destination_ip": target,
                    "distinct_ports": event.get("distinct_ports"),
                    "sample_ports": event.get("sample_ports"),
                    "window_seconds": event.get("window_seconds"),
                    "action": event.get("action"),
                    "line_number": number,
                })
            except (
                ValueError, KeyError, TypeError, OverflowError,
                OSError,
            ):
                malformed += 1

    return {
        "source": "opla_scan_detector",
        "status": "analyzed",
        "matching_events": len(matched),
        "malformed_records": malformed,
        "events": matched,
        "timestamp_precision": "seconds",
        "causal_attribution": "unverified",
        "complete_log_coverage": "unverified",
    }


def build_report(experiment, eve_path=None, scan_path=None, *, max_client_gap_seconds=2):
    experiment = Path(experiment)

    if experiment.is_symlink() or not experiment.is_dir():
        raise ValueError("invalid experiment directory")

    interval = read_json(experiment / "interval.json")
    if interval.get("schema_version") != 1:
        raise ValueError("unsupported interval schema")

    start = interval["start"]
    end = interval["end"]
    source = str(ipaddress.ip_address(interval["source_ip"]))
    target = str(ipaddress.ip_address(interval["target_ip"]))

    if eve.parse_time(end) < eve.parse_time(start):
        raise ValueError("invalid interval ordering")

    before = read_json(experiment / "before.json")
    after = read_json(experiment / "after.json")

    result = {
        "schema_version": 1,
        "mode": "offline_incident_report",
        "experiment": experiment.name,
        "actual_execution_by_reporter": False,
        "interval": interval,
        "counters": counters.correlate(before, after),
        "suricata": {
            "status": "unavailable",
            "reason": "EVE log not supplied",
        },
        "scan_detector": {
            "status": "unavailable",
            "reason": "scan event log not supplied",
        },
        "attack_attribution": "unverified",
        "client_continuity": client_continuity_report(
            experiment, interval, max_gap_seconds=max_client_gap_seconds),
    }

    if eve_path is not None:
        result["suricata"] = {
            "status": "analyzed",
            **eve.correlate_eve(
                eve_path, start, end, source, target
            ),
        }

    if scan_path is not None:
        result["scan_detector"] = scan_events(
            scan_path, start, end, source, target
        )

    result["evidence_exports"] = {}

    for kind in ("suricata", "scan"):
        meta_file = experiment / f"{kind}-evidence-meta.json"
        error_file = experiment / f"{kind}-export-error.txt"

        if meta_file.is_file() and not meta_file.is_symlink():
            result["evidence_exports"][kind] = read_json(meta_file)
        else:
            result["evidence_exports"][kind] = {
                "status": "unavailable",
                "coverage": "unavailable",
                "reason": "export metadata not available",
            }

            if error_file.is_file() and not error_file.is_symlink():
                result["evidence_exports"][kind]["error_log"] = error_file.name

    sources = result["evidence_exports"]

    result["evidence_quality"] = {
        "status": (
            "unavailable"
            if all(
                source.get("status") != "captured"
                for source in sources.values()
            )
            else "partial_or_unverified"
        ),
        "sources": {
            kind: {
                "status": source.get("status", "unknown"),
                "coverage": source.get("coverage", "unknown"),
                "truncated": source.get("truncated"),
            }
            for kind, source in sources.items()
        },
        "complete_evidence_verified": False,
    }

    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", type=Path)
    parser.add_argument("--eve", type=Path)
    parser.add_argument("--scan-events", type=Path)
    args = parser.parse_args()

    try:
        report = build_report(
            args.experiment, args.eve, args.scan_events
        )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    except (
        OSError, ValueError, KeyError, TypeError, UnicodeError,
    ) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
