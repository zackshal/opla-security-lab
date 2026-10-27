#!/usr/bin/env python3
"""OPLA laboratory lifecycle orchestration contracts.

Read-only CLI. Actual execution will require a trusted installation,
lifecycle locks and explicit authorization.
"""

import argparse
import json
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
