#!/usr/bin/env python3
"""OPLA scenario execution adapter: simulation only."""

import argparse
import importlib.util
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "bin/opla-scenario.py"

spec = importlib.util.spec_from_file_location("opla_scenario", ENGINE)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

ALLOWED_KINDS = frozenset({
    "xdp-observe",
    "syn-scan",
    "http-probe",
})


def execute_plan(plan, handler):
    """Dispatch validated stages; stop on the first failure."""
    if plan.get("execution_enabled") is not False:
        raise ValueError("unexpected execution state")

    results = []
    for stage in plan["experiments"]:
        kind = stage["kind"]

        if kind not in ALLOWED_KINDS:
            raise ValueError(f"unsupported stage: {kind}")

        try:
            details = handler(stage)
            results.append({
                "id": stage["id"],
                "kind": kind,
                "status": "simulated",
                "details": details,
            })
        except Exception as exc:
            results.append({
                "id": stage["id"],
                "kind": kind,
                "status": "failed",
                "error": str(exc),
            })
            break

    return {
        "schema_version": 1,
        "run_id": uuid.uuid4().hex,
        "scenario": plan["scenario"],
        "mode": "simulation",
        "actual_execution": False,
        "telemetry_collected": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": (
            "simulation_completed"
            if len(results) == len(plan["experiments"])
            and all(r["status"] == "simulated" for r in results)
            else "simulation_failed"
        ),
        "steps": results,
    }


def simulate_stage(stage):
    return {
        "dispatch_validated": True,
        "target": stage.get("target"),
        "source": stage.get("source"),
        "note": "No VM, traffic, eBPF or Suricata action performed",
    }


def save_report(report, directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)

    target = directory / f"{report['run_id']}.json"
    if target.exists():
        raise FileExistsError("report identifier collision")

    descriptor, temporary = tempfile.mkstemp(
        prefix=".report-",
        suffix=".tmp",
        dir=directory,
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["simulate"])
    parser.add_argument("scenario")
    args = parser.parse_args()

    try:
        scenario = engine.load_scenario(args.scenario)
        plan = engine.validate(scenario)

        if plan["scenario"] != args.scenario:
            raise ValueError("scenario identifier mismatch")

        report = execute_plan(plan, simulate_stage)

        directory = (
            Path.home() / ".local/state/opla-scenarios"
        )
        path = save_report(report, directory)

        print(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"Report: {path}", file=sys.stderr)

        return 0 if report["status"] == "simulation_completed" else 1

    except (OSError, ValueError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
