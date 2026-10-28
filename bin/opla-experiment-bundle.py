#!/usr/bin/env python3
"""Build an offline evidence bundle from an existing OPLA experiment."""

import argparse
import hashlib
import json
import math
import os
import tempfile
import stat
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
    "client-probes.json",
)

MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
REPORT_INPUTS = ("interval.json", "before.json", "after.json", "eve.json", "events.jsonl")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_stable(path):
    """Read a pinned regular file and reject replacement during the read."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"unsafe evidence file: {path.name}")
        data = bytearray()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            data.extend(block)
            if len(data) > MAX_EVIDENCE_BYTES:
                raise ValueError(f"evidence exceeds byte limit: {path.name}")
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_nlink)
                != (after.st_dev, after.st_ino, after.st_size, after.st_nlink)):
            raise ValueError(f"evidence changed during read: {path.name}")
        return bytes(data)
    finally:
        os.close(descriptor)


def inventory_file(path):
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return {"status": "unsafe"}
        if st.st_size > MAX_EVIDENCE_BYTES:
            return {"status": "not_hashed_size_limit", "size_bytes": st.st_size}
        data = _read_stable(path)
    except (OSError, ValueError):
        return {"status": "missing"}
    return {"status": "present", "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def _snapshot(experiment, evidence):
    root = Path(tempfile.mkdtemp(prefix="opla-report-snapshot-"))
    snapshot = root / experiment.name
    snapshot.mkdir()
    try:
        for name in (*EVIDENCE_FILES, *REPORT_INPUTS):
            if evidence.get(name, {}).get("status") != "present":
                continue
            data = _read_stable(experiment / name)
            (snapshot / name).write_bytes(data)
        return root, snapshot
    except Exception:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
        raise


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


def _validate_timeout(timeout):
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("reporter timeout must be finite and positive")


def build(experiment, *, runner=None, timeout=30):
    _validate_timeout(timeout)
    experiment = experiment.resolve(strict=True)

    if not experiment.is_dir():
        raise ValueError("Experiment must be an existing directory")

    if not experiment.name.startswith("scenario-"):
        raise ValueError("Expected reports/scenario-* experiment directory")

    output = experiment / "pipeline"
    output.mkdir(exist_ok=True)

    evidence = {}
    for name in EVIDENCE_FILES:
        evidence[name] = inventory_file(experiment / name)

    snapshot_root = snapshot = None

    incident = None
    report_error = None

    dispatch = subprocess.run if runner is None else runner
    try:
        snapshot_root, snapshot = _snapshot(experiment, evidence)
        report_command = [sys.executable, str(ROOT / "bin/opla-incident-report.py"), str(snapshot)]
        if evidence["eve.json"]["status"] == "present":
            report_command += ["--eve", str(snapshot / "eve.json")]
        if evidence["events.jsonl"]["status"] == "present":
            report_command += ["--scan-events", str(snapshot / "events.jsonl")]
        result = dispatch(
            report_command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        report_error = f"Incident reporter dispatch failed: {type(exc).__name__}: {exc}"
    except ValueError as exc:
        report_error = f"Incident evidence snapshot failed: {exc}"
    else:
        if result.returncode == 0:
            try:
                candidate = json.loads(result.stdout)
                if not isinstance(candidate, dict):
                    raise ValueError("incident report must be an object")
                coverage = candidate.get("client_continuity")
                if not isinstance(coverage, dict):
                    raise ValueError("incident report lacks client continuity")
                inventoried = evidence["client-probes.json"]
                if inventory_file(experiment / "client-probes.json") != inventoried:
                    raise ValueError("client evidence changed after inventory")
                reported_hash = coverage.get("artifact_sha256")
                if inventoried["status"] == "present":
                    if reported_hash != inventoried["sha256"]:
                        raise ValueError("client evidence changed after inventory")
                elif reported_hash is not None or coverage.get("status") != "unavailable":
                    raise ValueError("client evidence changed after inventory")
                for name in REPORT_INPUTS:
                    if inventory_file(experiment / name) != evidence[name]:
                        raise ValueError(f"report input changed after inventory: {name}")
                incident = candidate
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
    if snapshot_root is not None:
        import shutil
        shutil.rmtree(snapshot_root, ignore_errors=True)

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
