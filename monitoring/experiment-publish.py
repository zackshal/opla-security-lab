#!/usr/bin/env python3
"""Publish a verified offline OPLA bundle envelope to existing Zabbix."""

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "monitoring"))

from bridge import send

LAB_ID_RE = re.compile(r"lab-[A-Za-z0-9_-]+")
MAX_BYTES = 2 * 1024 * 1024


def load_json(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Missing or unsafe file: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"Oversized JSON: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(experiment, lab_id):
    if not LAB_ID_RE.fullmatch(lab_id):
        raise ValueError("Expected lab ID: lab-XXXXXXXX")

    experiment = Path(experiment).resolve(strict=True)
    if not experiment.is_dir() or not experiment.name.startswith("scenario-"):
        raise ValueError("Expected an existing scenario-* directory")

    pipeline = experiment / "pipeline"
    manifest_path = pipeline / "manifest.json"
    metrics_path = pipeline / "monitoring-metrics.json"

    manifest = load_json(manifest_path)
    metrics = load_json(metrics_path)

    if manifest.get("schema_version") != 1:
        raise ValueError("Unsupported manifest schema")
    if metrics.get("schema_version") != 1:
        raise ValueError("Unsupported metrics schema")

    if manifest.get("experiment") != experiment.name:
        raise ValueError("Manifest experiment mismatch")
    if metrics.get("experiment") != experiment.name:
        raise ValueError("Metrics experiment mismatch")

    status = manifest.get("incident_report_status")
    if status not in ("generated", "blocked"):
        raise ValueError("Invalid report status")

    generated = metrics.get("metrics", {}).get(
        "opla.incident_report.generated"
    )
    if type(generated) is not int or generated != int(status == "generated"):
        raise ValueError("Report status and metrics disagree")

    report_hash = None
    if status == "generated":
        report_path = pipeline / "incident-report.json"
        report = load_json(report_path)
        report_hash = digest(report_path)
        if report_hash != manifest.get("incident_report_sha256"):
            raise ValueError("Incident report SHA-256 mismatch")
        if report.get("evidence_quality") != manifest.get("evidence_quality"):
            raise ValueError("Incident evidence quality mismatch")

    event = {
        "schema_version": 1,
        "event": "opla_experiment_completed",
        "lab_id": lab_id,
        "experiment": experiment.name,
        "report_status": status,
        "report_error": manifest.get("incident_report_error"),
        "evidence_quality": manifest.get("evidence_quality"),
        "metrics": metrics["metrics"],
        "manifest_sha256": digest(manifest_path),
        "incident_report_sha256": report_hash,
        "collected_at": manifest.get("created_at"),
    }

    return {
        "host": f"opla-{lab_id}",
        "key": "opla.experiment.event",
        "value": json.dumps(event, ensure_ascii=False, separators=(",", ":")),
        "clock": int(time.time()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", required=True)
    parser.add_argument("--experiment", required=True)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and print the Zabbix record without sending it",
    )
    args = parser.parse_args()

    try:
        record = prepare(args.experiment, args.lab)

        if args.dry_run:
            print(json.dumps(record, ensure_ascii=False, indent=2))
            return 0

        response = send([record])
        print(f"Zabbix accepted experiment: {record['host']}")
        print(response)
        return 0

    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"BLOCKED: experiment publication: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
