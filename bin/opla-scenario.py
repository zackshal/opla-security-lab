#!/usr/bin/env python3
"""OPLA scenario validation and read-only planning."""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"

EXPECTED_ROLES = {
    "attacker": {"memory_mib": 1024, "vcpus": 1},
    "victim": {"memory_mib": 2048, "vcpus": 2},
    "client": {"memory_mib": 512, "vcpus": 1},
}

ROLE_IMAGES = {
    "attacker": "debian-12-attacker.qcow2",
    "victim": "debian-12-xdp.qcow2",
    "client": "debian-12-client.qcow2",
}

EXPERIMENTS = {
    "xdp-observe": {
        "required": {"id", "kind", "target"},
        "roles": {"target": {"victim"}},
    },
    "syn-scan": {
        "required": {"id", "kind", "source", "target"},
        "roles": {
            "source": {"attacker"},
            "target": {"victim"},
        },
    },
    "http-probe": {
        "required": {"id", "kind", "source", "target"},
        "roles": {
            "source": {"client"},
            "target": {"victim"},
        },
    },
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_scenario(name):
    require(
        re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is not None,
        "invalid scenario identifier",
    )

    directory = SCENARIOS.resolve(strict=True)
    path = directory / f"{name}.yaml"

    require(not path.is_symlink(), "scenario symlink forbidden")
    require(path.is_file(), "scenario not found")
    require(
        path.resolve().parent == directory,
        "scenario outside trusted directory",
    )
    require(path.stat().st_size <= 65536, "scenario too large")

    with path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)

    require(type(data) is dict, "scenario must be a mapping")
    return data


def validate(data):
    require(
        set(data) == {
            "schema_version", "id", "platform",
            "topology", "experiments",
        },
        "unexpected or missing scenario fields",
    )
    require(
        type(data["schema_version"]) is int
        and data["schema_version"] == 1,
        "unsupported schema version",
    )
    require(
        type(data["id"]) is str
        and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", data["id"]),
        "invalid scenario id",
    )
    require(
        data["platform"] == "debian-amd64",
        "unsupported platform",
    )

    topology = data["topology"]
    require(
        type(topology) is dict
        and set(topology) == {"network", "roles"},
        "invalid topology",
    )
    require(topology["network"] == "isolated", "non-isolated network forbidden")
    require(
        type(topology["roles"]) is dict
        and topology["roles"] == EXPECTED_ROLES,
        "role resources do not match the current launcher",
    )

    stages = data["experiments"]
    require(
        type(stages) is list and 1 <= len(stages) <= 16,
        "invalid experiment count",
    )

    seen = set()

    for stage in stages:
        require(type(stage) is dict, "invalid experiment entry")
        kind = stage.get("kind")
        require(
            type(kind) is str and kind in EXPERIMENTS,
            "unsupported experiment kind",
        )

        contract = EXPERIMENTS[kind]
        require(
            set(stage) == contract["required"],
            "invalid experiment fields",
        )

        stage_id = stage["id"]
        require(
            type(stage_id) is str
            and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", stage_id),
            "invalid experiment id",
        )
        require(stage_id not in seen, "duplicate experiment id")
        seen.add(stage_id)

        for field, permitted in contract["roles"].items():
            require(
                type(stage[field]) is str
                and stage[field] in permitted,
                f"invalid {field} role for {kind}",
            )

    return {
        "schema_version": 1,
        "scenario": data["id"],
        "platform": data["platform"],
        "execution_enabled": False,
        "network": "isolated",
        "vms": [
            {
                "role": role,
                "image": ROLE_IMAGES[role],
                **resources,
            }
            for role, resources in EXPECTED_ROLES.items()
        ],
        "experiments": stages,
        "total_memory_mib": sum(
            entry["memory_mib"]
            for entry in EXPECTED_ROLES.values()
        ),
        "total_vcpus": sum(
            entry["vcpus"]
            for entry in EXPECTED_ROLES.values()
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="OPLA read-only scenario engine"
    )
    parser.add_argument("command", choices=("validate", "plan"))
    parser.add_argument("scenario")
    args = parser.parse_args()

    try:
        data = load_scenario(args.scenario)
        plan = validate(data)
        require(
            data["id"] == args.scenario,
            "scenario filename/id mismatch",
        )
    except (ValueError, OSError, yaml.YAMLError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate":
        print(f"PASS: scenario {args.scenario}")
    else:
        print(json.dumps(plan, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    sys.exit(main())
