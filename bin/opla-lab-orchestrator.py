#!/usr/bin/env python3
"""OPLA laboratory lifecycle orchestration contracts.

Read-only CLI. Actual execution will require a trusted installation,
lifecycle locks and explicit authorization.
"""

import argparse
import asyncio
import importlib.util
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path

LAB = re.compile(r"lab-[A-Za-z0-9]{4,32}\Z")


@dataclass(frozen=True)
class Step:
    name: str
    dependency: str | None
    action: str


PLAN = (
    Step(
        "preflight",
        None,
        "Verify host resources, images and trusted source",
    ),
    Step(
        "create",
        "preflight",
        "Invoke verified create launcher",
    ),
    Step(
        "configure",
        "create",
        "Run guarded ready/XDP/Suricata configuration",
    ),
    Step(
        "health",
        "configure",
        "Verify real XDP and IDS functionality",
    ),
)

ACCEPTANCE_STEPS = tuple(step.name for step in PLAN) + (
    "scenario", "telemetry", "report",
)
REQUIRED_PROBES = {
    "preflight": ("dependencies", "images", "management_separate"),
    "create": ("ownership", "registry", "three_vms", "cloud_init"),
    "configure": ("ownership", "xdp_loaded", "suricata_active"),
    "health": ("ownership", "xdp_loaded", "suricata_active", "client_alive"),
    "scenario": ("ownership", "bounded_traffic", "client_alive"),
    "telemetry": ("ownership", "xdp_counters", "suricata_events", "correlation"),
    "report": ("ownership", "report_generated", "evidence_complete"),
}


def load_progress():
    spec = importlib.util.spec_from_file_location(
        "opla_lifecycle_progress", Path(__file__).with_name("opla-lab-progress.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


progress = load_progress()


class ProbeFailure(ValueError):
    def __init__(self, message, evidence):
        super().__init__(message)
        self.evidence = evidence


class StageTimeout(TimeoutError):
    """A cancellable offline stage deadline with durable evidence."""

    def __init__(self, stage, timeout):
        self.evidence = {
            "deadline": {
                "stage": stage,
                "timeout_seconds": timeout,
                "kind": "stage_timeout",
            }
        }
        super().__init__(f"TimeoutError: {stage} exceeded {timeout} second deadline")


def _validate_deadline(value, label):
    if (isinstance(value, bool) or not isinstance(value, (float, int))
            or not math.isfinite(value) or value <= 0):
        raise ValueError(f"{label} must be finite and positive")


def run_acceptance(adapter, journal_path, lab_id, *, resume=False, timeout=30.0,
                   stage_timeouts=None):
    """Persistent OFFLINE acceptance using an injected asynchronous adapter.

    adapter.mode must be 'offline'. execute(step, lab_id) returns action evidence;
    probe(step, lab_id) returns independent observations including lab_id and
    strict boolean checks in REQUIRED_PROBES. Both methods must be cancellable
    coroutines; they must not block the event loop. No live adapter is enabled.
    Each action/probe has its own deadline. Creation failure is never replayed.
    """
    if getattr(adapter, "mode", None) != "offline":
        raise progress.Blocked("only offline adapters are enabled")
    _validate_deadline(timeout, "timeout")
    if stage_timeouts is not None:
        if not isinstance(stage_timeouts, dict):
            raise ValueError("stage_timeouts must be a mapping")
        unknown = set(stage_timeouts) - set(ACCEPTANCE_STEPS)
        if unknown:
            raise ValueError(f"unknown stage timeout(s): {sorted(unknown)}")
        for step, value in stage_timeouts.items():
            _validate_deadline(value, f"stage timeout for {step}")
    else:
        stage_timeouts = {}

    def deadline(step):
        return stage_timeouts.get(step, timeout)

    async def bounded(method, step):
        budget = deadline(step)
        try:
            return await asyncio.wait_for(method(step, lab_id), timeout=budget)
        except asyncio.TimeoutError as exc:
            raise StageTimeout(step, budget) from exc

    def probe(step):
        evidence = asyncio.run(bounded(adapter.probe, step))
        if not isinstance(evidence, dict) or evidence.get("lab_id") != lab_id:
            raise ValueError(f"{step}: probe identity mismatch")
        json.dumps(evidence, allow_nan=False)
        if any(evidence.get(key) is not True for key in REQUIRED_PROBES[step]):
            raise ProbeFailure(f"{step}: required probes failed or missing", evidence)
        return evidence

    def execute(step):
        index = ACCEPTANCE_STEPS.index(step)
        if index:
            probe(ACCEPTANCE_STEPS[index - 1])
        action = asyncio.run(bounded(adapter.execute, step))
        if not isinstance(action, dict) or action.get("lab_id") != lab_id:
            raise ValueError(f"{step}: action identity mismatch")
        try:
            return {"action": action, "probe": probe(step)}
        except ProbeFailure as exc:
            exc.evidence = {"action": action, "probe": exc.evidence}
            raise

    try:
        state = progress.run_offline(
            execute, journal_path, lab_id, resume=resume,
            steps=ACCEPTANCE_STEPS, revalidate=lambda step: bool(probe(step)),
            restore=getattr(adapter, "restore", None),
            bind_checkpoint=getattr(adapter, "bind_checkpoint", None),
        )
    except progress.Blocked as exc:
        return {
            "schema_version": 1, "mode": "offline", "actual_execution": False,
            "live_status": "NOT TESTED", "lab_id": lab_id,
            "status": "BLOCKED", "exit_code": 2, "error": str(exc),
            "steps": {name: {"status": "NOT TESTED"} for name in ACCEPTANCE_STEPS},
        }
    passed = all(record["status"] == "PASS" for record in state["steps"].values())
    return {
        "schema_version": 1,
        "mode": "offline",
        "actual_execution": False,
        "live_status": "NOT TESTED",
        "lab_id": lab_id,
        "status": "PASS" if passed else "FAILED",
        "exit_code": 0 if passed else 1,
        "steps": {
            name: {**record, "status": (
                "NOT TESTED" if record["status"] == "PENDING" else record["status"]
            )}
            for name, record in state["steps"].items()
        },
    }


def run_steps(executor, journal=None):
    """Execute an injected test executor without host commands."""
    results = {}

    for step in PLAN:
        if (
            step.dependency
            and results[step.dependency] != "PASS"
        ):
            results[step.name] = "NOT RUN"
            continue

        try:
            success = executor(step.name)
        except Exception:
            success = False

        results[step.name] = (
            "PASS" if success is True else "FAILED"
        )

    if journal is not None:
        journal(results)

    return results


def validate_contract(root):
    """Read-only verification of existing lifecycle entry points."""
    root = Path(root)

    paths = {
        "create": root / "bin/opla-create-launcher.py",
        "configure": (
            root / "bin/opla-lab-configure-launcher.py"
        ),
        "script": root / "bin/opla-lab-configure.sh",
        "make": root / "Makefile",
    }

    for name, path in paths.items():
        if path.is_symlink() or not path.is_file():
            raise ValueError(
                f"{name}: missing or symlink"
            )

    makefile = paths["make"].read_text(
        encoding="utf-8"
    )
    script = paths["script"].read_text(
        encoding="utf-8"
    )

    checks = {
        "make creation": (
            "bin/opla-create-launcher.py" in makefile
        ),
        "make configure": (
            "bin/opla-lab-configure-launcher.py" in makefile
        ),
        "cloud init readiness": (
            "make --no-print-directory ready" in script
        ),
        "xdp configuration": (
            "make --no-print-directory xdp-all" in script
        ),
        "suricata service": (
            "opla-suricata.service" in script
        ),
    }

    missing = [
        name
        for name, passed in checks.items()
        if not passed
    ]

    if missing:
        raise ValueError(
            "missing integration contracts: "
            + ", ".join(missing)
        )

    return checks


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "action",
        choices=("plan", "check"),
    )
    parser.add_argument(
        "--source",
        default=str(
            Path(__file__).resolve().parents[1]
        ),
    )
    parser.add_argument(
        "--lab",
        help="Existing lab identifier, planning only",
    )

    args = parser.parse_args(argv)

    if args.lab and not LAB.fullmatch(args.lab):
        parser.error("invalid lab identifier")

    try:
        checks = validate_contract(args.source)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2

    if args.action == "check":
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "contracts": checks,
                },
                indent=2,
            )
        )
    else:
        print(
            json.dumps(
                {
                    "mode": "READ-ONLY",
                    "lab": args.lab,
                    "steps": [
                        {
                            "name": step.name,
                            "depends_on": step.dependency,
                            "action": step.action,
                            "status": "NOT RUN",
                        }
                        for step in PLAN
                    ],
                    "execution": (
                        "BLOCKED until trusted installer "
                        "and locks are integrated"
                    ),
                },
                indent=2,
            )
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
