#!/usr/bin/env python3
"""OPLA live scenario adapter for an already running authorized lab."""

import argparse
import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = Path("/var/lib/opla")
AUTH_FILE = Path("/etc/opla/executor-authorized")
MIN_RAM_KIB = 5 * 1024 * 1024

spec = importlib.util.spec_from_file_location(
    "opla_scenario_live_engine",
    ROOT / "bin/opla-scenario.py",
)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


evidence_spec = importlib.util.spec_from_file_location(
    "opla_xdp_evidence_live",
    ROOT / "bin/opla-xdp-evidence.py",
)
evidence = importlib.util.module_from_spec(evidence_spec)
evidence_spec.loader.exec_module(evidence)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def call(argv, env=None, timeout=180):
    return subprocess.run(
        argv,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def executor_authorized():
    require(os.geteuid() == 0, "execution requires root on executor")

    os_release = Path("/etc/os-release").read_text()
    require(
        'ID=debian' in os_release
        and 'VERSION_ID="12"' in os_release,
        "live adapter currently supports Debian 12 only",
    )

    require(not AUTH_FILE.is_symlink(), "unsafe executor marker")
    require(AUTH_FILE.is_file(), "executor is not authorized")

    stat = AUTH_FILE.stat()
    require(
        stat.st_uid == 0 and stat.st_mode & 0o022 == 0,
        "executor authorization permissions are unsafe",
    )
    require(
        AUTH_FILE.read_text().strip() == "OPLA_EXECUTOR_V1",
        "invalid executor authorization",
    )

    memory = Path("/proc/meminfo").read_text()
    match = re.search(r"^MemTotal:\s+(\d+)\s+kB", memory, re.M)
    require(
        match is not None and int(match.group(1)) >= MIN_RAM_KIB,
        "executor requires at least 5 GiB RAM",
    )


def validate_lab(lab_id):
    require(
        re.fullmatch(r"lab-[A-Za-z0-9]+", lab_id) is not None,
        "invalid lab ID",
    )

    lab = LAB_ROOT / lab_id
    require(not lab.is_symlink() and lab.is_dir(), "lab unavailable")

    receipt = LAB_ROOT / "registry" / f"{lab_id}.json"
    require(
        not receipt.is_symlink() and receipt.is_file(),
        "registry receipt missing",
    )

    record = json.loads(receipt.read_text())
    require(
        record.get("schema") == 1
        and record.get("lab_id") == lab_id
        and record.get("lab_dir") == str(lab)
        and record.get("phase") == "ready",
        "lab receipt is not ready",
    )

    registry_spec = importlib.util.spec_from_file_location(
        "opla_registry_live",
        ROOT / "bin/opla-registry.py",
    )
    registry = importlib.util.module_from_spec(registry_spec)
    registry_spec.loader.exec_module(registry)

    expected = registry.receipt(LAB_ROOT, lab_id, "ready")

    def resource_set(items):
        return sorted((x["kind"], x["name"]) for x in items)

    require(
        resource_set(record["resources"])
        == resource_set(expected["resources"]),
        "registry resources differ from expected lab state",
    )

    env = os.environ.copy()
    env["LAB_DIR"] = str(lab)

    state = ROOT / "bin/state.py"

    addresses = {}
    for role in ("attacker", "victim", "client"):
        key = role.upper() + "_IP"
        result = call(
            [sys.executable, str(state), str(lab), key],
            env=env,
            timeout=10,
        )
        require(result.returncode == 0, f"missing {key}")
        addresses[role] = str(
            ipaddress.IPv4Address(result.stdout.strip())
        )

        unit = f"qemu-{lab_id}-{role}.service"
        active = call(
            ["systemctl", "is-active", "--quiet", unit],
            timeout=5,
        )
        require(active.returncode == 0, f"{role} VM not running")

    return lab, env, addresses


def read_scan_evidence(output):
    """Read snapshots from the report directory printed by traffic-scenario."""
    matches = re.findall(
        r"^Материалы опыта:\\s*(reports/scenario-syn-[A-Za-z0-9]+)\\s*$",
        output,
        re.MULTILINE,
    )
    require(len(matches) == 1, "scan report directory not identified")

    base = (ROOT / "reports").resolve()
    directory = ROOT / matches[0]

    require(not directory.is_symlink(), "unsafe scan report directory")
    require(
        directory.resolve().parent == base,
        "scan report directory outside reports/",
    )

    snapshots = []
    for name in ("before.json", "after.json"):
        path = directory / name
        require(
            path.is_file() and not path.is_symlink(),
            f"missing or unsafe XDP snapshot: {name}",
        )
        snapshots.append(path)

    result = evidence.analyze_files(*snapshots)
    result["report_directory"] = matches[0]
    return result


def run_stage(stage, env, addresses):
    kind = stage["kind"]

    if kind == "xdp-observe":
        argv = ["bash", "bin/xdp-scan-policy.sh", "observe"]

    elif kind == "syn-scan":
        argv = ["bash", "bin/traffic-scenario.sh", "syn"]

    elif kind == "http-probe":
        # IP addresses come from the validated lab state, not from YAML.
        script = """
set -euo pipefail
source xdp/lib.sh
ssh_vm "$OPLA_CLIENT_IP" \\
  "curl --fail --max-time 10 -sS -o /dev/null -w 'HTTP=%{http_code}\\\\n' 'http://$OPLA_VICTIM_IP/'"
"""
        env = env.copy()
        env["OPLA_CLIENT_IP"] = addresses["client"]
        env["OPLA_VICTIM_IP"] = addresses["victim"]
        argv = ["bash", "-c", script]

    else:
        raise RuntimeError(f"unsupported action: {kind}")

    result = call(argv, env=env, timeout=180)

    item = {
        "id": stage["id"],
        "kind": kind,
        "status": "completed" if result.returncode == 0 else "failed",
        "exit_code": result.returncode,
        "stdout": result.stdout[-16000:],
        "stderr": result.stderr[-16000:],
    }

    if kind == "syn-scan":
        try:
            item["evidence"] = read_scan_evidence(result.stdout)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            item["status"] = "failed"
            item["evidence_error"] = str(exc)

    return item


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "run"))
    parser.add_argument("scenario")
    parser.add_argument("--lab", required=True)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()

    try:
        scenario = engine.load_scenario(args.scenario)
        plan = engine.validate(scenario)
        require(plan["scenario"] == args.scenario, "scenario ID mismatch")

        # Check executor before any live action.
        executor_authorized()
        lab, env, addresses = validate_lab(args.lab)

        if args.command == "check":
            print(json.dumps({
                "scenario": args.scenario,
                "lab": args.lab,
                "ready_for_attempt": True,
                "actual_execution": False,
                "note": "Static and runtime prechecks passed; no traffic sent",
            }, indent=2))
            return 0

        require(
            args.confirm == args.lab,
            "explicit --confirm <lab_id> required",
        )

        results = []
        for stage in plan["experiments"]:
            try:
                item = run_stage(stage, env, addresses)
            except (
                RuntimeError, OSError, ValueError,
                subprocess.TimeoutExpired,
            ) as exc:
                item = {
                    "id": stage["id"],
                    "kind": stage["kind"],
                    "status": "failed",
                    "error": str(exc),
                }

            results.append(item)
            if item["status"] != "completed":
                break

        scan_evidence = [
            item.get("evidence")
            for item in results
            if item["kind"] == "syn-scan"
            and item.get("evidence", {}).get("telemetry_collected") is True
        ]

        report = {
            "schema_version": 1,
            "run_id": uuid.uuid4().hex,
            "mode": "live",
            "scenario": args.scenario,
            "lab": args.lab,
            "actual_execution": True,
            "steps": results,
            "status": (
                "completed"
                if len(results) == len(plan["experiments"])
                and all(x["status"] == "completed" for x in results)
                else "failed"
            ),
            "telemetry_collected": bool(scan_evidence),
        }

        directory = Path("/var/lib/opla-scenario-reports")
        directory.mkdir(mode=0o700, exist_ok=True)

        target = directory / f"{args.lab}-{report['run_id']}.json"
        fd = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\\n")
            stream.flush()
            os.fsync(stream.fileno())

        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "completed" else 1

    except (
        RuntimeError, OSError, ValueError, KeyError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
