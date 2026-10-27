#!/usr/bin/env python3
"""Build an offline evidence bundle from an existing OPLA experiment."""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EVIDENCE_FILES = (
    "context.txt",
    "interval.json",
    "before.json",
    "after.json",
    "fingerprint-before.json",
    "fingerprint-after.json",
    "generator.txt",
    "generator-exit.txt",
    "eve.json",
    "events.jsonl",
    "suricata-evidence-meta.json",
    "scan-evidence-meta.json",
)

MAX_EVIDENCE_BYTES = 32 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path, data):
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def build(experiment):
    experiment = experiment.resolve(strict=True)

    if not experiment.is_dir():
        raise ValueError("Experiment must be an existing directory")

    if not experiment.name.startswith("scenario-"):
        raise ValueError("Expected reports/scenario-* experiment directory")

    output = experiment / "pipeline"
    output.mkdir(exist_ok=True)

    evidence = {}
    for name in EVIDENCE_FILES:
        path = experiment / name
        if not path.is_file() or path.is_symlink():
            evidence[name] = {"status": "missing"}
            continue

        size = path.stat().st_size
        if size > MAX_EVIDENCE_BYTES:
            evidence[name] = {
                "status": "not_hashed_size_limit",
                "size_bytes": size,
            }
            continue

        evidence[name] = {
            "status": "present",
            "size_bytes": size,
            "sha256": sha256(path),
        }

    report_command = [
        sys.executable,
        str(ROOT / "bin/opla-incident-report.py"),
        str(experiment),
    ]

    if evidence["eve.json"]["status"] == "present":
        report_command += ["--eve", str(experiment / "eve.json")]

    if evidence["events.jsonl"]["status"] == "present":
        report_command += [
            "--scan-events",
            str(experiment / "events.jsonl"),
        ]

    result = subprocess.run(
        report_command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    incident = None
    report_error = None

    if result.returncode == 0:
        try:
            incident = json.loads(result.stdout)
            save_json(output / "incident-report.json", incident)
        except (ValueError, TypeError) as exc:
            report_error = f"Invalid incident JSON: {exc}"
    else:
        report_error = (
            result.stderr.strip()
            or f"Incident reporter exit code: {result.returncode}"
        )

    if report_error:
        (output / "incident-report.json").unlink(missing_ok=True)

    # Status indicates report generation, NOT completeness or attack attribution.
    report_status = "generated" if incident is not None else "blocked"

    manifest = {
        "schema_version": 1,
        "experiment": experiment.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "incident_report_status": report_status,
        "incident_report_error": report_error,
        "evidence": evidence,
    }

    if incident is not None:
        manifest["incident_report_sha256"] = sha256(
            output / "incident-report.json"
        )
        manifest["evidence_quality"] = incident.get("evidence_quality")

    save_json(output / "manifest.json", manifest)

    # Offline export only. No Zabbix API calls or network changes.
    metrics = {
        "schema_version": 1,
        "experiment": experiment.name,
        "collected_at": manifest["created_at"],
        "metrics": {
            "opla.incident_report.generated": int(incident is not None),
            "opla.evidence.xdp_before.present": int(
                evidence["before.json"]["status"] == "present"
            ),
            "opla.evidence.xdp_after.present": int(
                evidence["after.json"]["status"] == "present"
            ),
            "opla.evidence.suricata.present": int(
                evidence["eve.json"]["status"] == "present"
            ),
            "opla.evidence.scan.present": int(
                evidence["events.jsonl"]["status"] == "present"
            ),
        },
    }
    save_json(output / "monitoring-metrics.json", metrics)

    print(f"Experiment: {experiment.name}")
    print(f"Incident report: {report_status}")
    if report_error:
        print(f"Reason: {report_error}", file=sys.stderr)
    print(f"Evidence manifest: {output / 'manifest.json'}")
    print(f"Monitoring metrics: {output / 'monitoring-metrics.json'}")

    return 0 if incident is not None else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", type=Path)
    args = parser.parse_args()

    try:
        return build(args.experiment)
    except (OSError, ValueError) as exc:
        print(f"OPLA bundle: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
