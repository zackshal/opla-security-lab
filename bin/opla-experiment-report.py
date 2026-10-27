#!/usr/bin/env python3
"""Create an offline report from an existing OPLA SYN experiment."""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"

spec = importlib.util.spec_from_file_location(
    "opla_xdp_evidence_report",
    ROOT / "bin/opla-xdp-evidence.py",
)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


def build_report(directory):
    directory = Path(directory)

    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("invalid experiment directory")

    if not re.fullmatch(r"scenario-syn-[A-Za-z0-9]+", directory.name):
        raise ValueError("invalid experiment directory name")

    if directory.resolve().parent != REPORTS.resolve():
        raise ValueError("experiment must be inside reports/")

    def read_file(name):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or unsafe file: {name}")
        return path.read_text(encoding="utf-8")

    before = json.loads(read_file("before.json"))
    after = json.loads(read_file("after.json"))
    generator_exit = read_file("generator-exit.txt").strip()

    if not re.fullmatch(r"[0-9]{1,3}", generator_exit):
        raise ValueError("invalid generator exit code")

    exit_code = int(generator_exit)
    if exit_code > 255:
        raise ValueError("generator exit code outside valid range")

    xdp = evidence.analyze(before, after)

    return {
        "schema_version": 1,
        "experiment": directory.name,
        "source": "existing_opla_artifacts",
        "mode": "offline_analysis",
        "actual_execution_by_reporter": False,
        "generator_exit_code": exit_code,
        "traffic_generated": (
            True if exit_code == 0 else None
        ),
        "traffic_observed": xdp["syn_packets_observed"],
        "attack_detected": None,
        "telemetry_collected": xdp["telemetry_collected"],
        "xdp": xdp,
        "limitations": [
            "Generator exit code does not prove the exact packet count.",
            "XDP counters may include unrelated traffic.",
            "No independent scan-detection event was verified.",
            "Suricata alerts were not analyzed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    args = parser.parse_args()

    try:
        report = build_report(args.directory)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
