#!/usr/bin/env python3
"""OPLA live scenario adapter for an already running authorized lab."""

import argparse
import importlib.util
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = Path("/var/lib/opla")
AUTH_FILE = Path("/etc/opla/executor-authorized")
MIN_RAM_KIB = 5 * 1024 * 1024
MAX_STAGE_OUTPUT_BYTES = 16 * 1024
MAX_REGISTRY_OUTPUT_BYTES = 16 * 1024
SUPPORTED_EXECUTOR_PLATFORMS = {("debian", "12"), ("debian", "13")}
TRUSTED_REGISTRY_HELPER = Path("/opt/opla/bin/opla-registry.py")
sys.path.insert(0, str(ROOT / "bin"))
from opla_process import run_bounded

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


fp_spec = importlib.util.spec_from_file_location(
    "opla_fingerprint_evidence_live",
    ROOT / "bin/opla-fingerprint-evidence.py",
)
fp_evidence = importlib.util.module_from_spec(fp_spec)
fp_spec.loader.exec_module(fp_evidence)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def call(argv, env=None, timeout=180, runner=None):
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or timeout <= 0 or not math.isfinite(timeout)):
        raise ValueError("stage timeout must be finite and positive")
    if runner is not None:
        return runner(
            argv,
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    return run_bounded(
        argv,
        cwd=ROOT,
        env=env,
        timeout=timeout,
        max_output_bytes=MAX_STAGE_OUTPUT_BYTES,
    )


def parse_os_release(raw):
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "VERSION_ID"}:
            if key in values:
                raise RuntimeError(f"duplicate {key} in /etc/os-release")
            values[key] = value.strip().strip('"').strip("'")
    return values.get("ID"), values.get("VERSION_ID")


def read_executor_authorization(path=AUTH_FILE):
    """Read the administrator's opt-in marker without following links."""
    path = Path(path)
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise RuntimeError("executor authorization directory is unavailable") from exc
    require(
        stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0
        and not parent.st_mode & 0o022,
        "executor authorization directory is unsafe",
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise RuntimeError("executor is not authorized; administrator marker is missing") from exc
    except OSError as exc:
        raise RuntimeError("cannot safely read executor authorization marker") from exc
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == 0 and not info.st_mode & 0o022
            and info.st_mode & 0o044,
            "executor authorization permissions are unsafe",
        )
        raw = os.read(fd, 129)
    finally:
        os.close(fd)
    require(raw == b"OPLA_EXECUTOR_V1\n", "invalid executor authorization marker")
    return True


def validate_executor_requirements(os_release, marker_valid, memory):
    platform = parse_os_release(os_release)
    require(
        platform in SUPPORTED_EXECUTOR_PLATFORMS,
        "live adapter requires Debian 12 or Debian 13 amd64",
    )
    require(marker_valid is True, "executor is not authorized")
    match = re.search(r"^MemTotal:\s+(\d+)\s+kB", memory, re.M)
    require(
        match is not None and int(match.group(1)) >= MIN_RAM_KIB,
        "executor requires at least 5 GiB RAM",
    )


def executor_authorized():
    """Require an explicit root-owned opt-in, but run as the lab operator."""
    validate_executor_requirements(
        Path("/etc/os-release").read_text(),
        read_executor_authorization(),
        Path("/proc/meminfo").read_text(),
    )


def validate_trusted_registry_helper(path=TRUSTED_REGISTRY_HELPER):
    """Permit only the protected installed registry reader to cross privilege."""
    path = Path(path)
    for directory in (path.parent, *path.parent.parents):
        try:
            info = directory.lstat()
        except OSError as exc:
            raise RuntimeError("trusted registry helper directory is unavailable") from exc
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and not info.st_mode & 0o022,
            "trusted registry helper directory is unsafe",
        )
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError("trusted registry helper is missing") from exc
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        and info.st_uid == 0 and not info.st_mode & 0o022
        and info.st_mode & 0o111,
        "trusted registry helper is unsafe",
    )
    return path


def inspect_registry(lab_id, expected_resources, *, runner=subprocess.run,
                     helper=TRUSTED_REGISTRY_HELPER):
    helper = validate_trusted_registry_helper(helper)
    try:
        result = runner(
            ["sudo", str(helper), "list", "--lab", lab_id],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("privileged read-only registry inspection failed") from exc
    require(result.returncode == 0, "privileged registry inspection failed")
    output = result.stdout
    require(
        isinstance(output, str) and len(output.encode("utf-8")) <= MAX_REGISTRY_OUTPUT_BYTES,
        "registry inspection output is invalid or too large",
    )
    try:
        records = json.loads(output)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("registry inspection returned invalid JSON") from exc
    require(isinstance(records, list) and len(records) == 1,
            "registry inspection did not return exactly one lab")
    record = records[0]
    require(
        isinstance(record, dict)
        and record.get("lab") == lab_id
        and record.get("file") == f"{lab_id}.json"
        and record.get("status") == "recorded"
        and type(record.get("resources")) is int
        and record["resources"] == expected_resources,
        "lab registry receipt is missing, stale, or incomplete",
    )
    state = record.get("state")
    required_state = {
        "LAB_ID", "BRIDGE", "SUBNET", "GW", "ATTACKER_IP", "VICTIM_IP",
        "CLIENT_IP", "MGMT_BRIDGE", "MGMT_SUBNET", "MGMT_GW",
        "ATTACKER_MGMT_IP", "VICTIM_MGMT_IP", "CLIENT_MGMT_IP",
    }
    require(
        isinstance(state, dict) and required_state <= state.keys()
        and state.get("LAB_ID") == lab_id,
        "registry inspection omitted validated lab network state",
    )
    return record


def validate_lab(lab_id):
    require(
        re.fullmatch(r"lab-[A-Za-z0-9]+", lab_id) is not None,
        "invalid lab ID",
    )

    lab = LAB_ROOT / lab_id
    require(not lab.is_symlink() and lab.is_dir(), "lab unavailable")

    record = inspect_registry(lab_id, 20)
    state_data = record["state"]

    env = os.environ.copy()
    env["LAB_DIR"] = str(lab)

    addresses = {}
    for role in ("attacker", "victim", "client"):
        key = role.upper() + "_IP"
        try:
            addresses[role] = str(ipaddress.IPv4Address(state_data[key]))
            ipaddress.ip_network(state_data["SUBNET"], strict=True)
            ipaddress.ip_network(state_data["MGMT_SUBNET"], strict=True)
        except (KeyError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
            raise RuntimeError(f"registry returned invalid network state for {key}") from exc

        unit = f"qemu-{lab_id}-{role}.service"
        active = call(
            ["systemctl", "is-active", "--quiet", unit],
            timeout=5,
        )
        require(active.returncode == 0, f"{role} VM not running")

    return lab, env, addresses


def read_scan_evidence(output):
    """Read snapshots from the report directory printed by traffic-scenario."""
    matches = []

    for line in output.splitlines():
        prefix = "Материалы опыта:"
        if line.startswith(prefix):
            candidate = line[len(prefix):].strip()
            if re.fullmatch(
                "reports/scenario-syn-[A-Za-z0-9]+",
                candidate,
            ):
                matches.append(candidate)

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

    fingerprint = fp_evidence.verify_directory(directory)
    result["fingerprint"] = fingerprint

    require(
        fingerprint["status"] == "verified",
        "XDP fingerprint not verified: "
        + fingerprint.get("reason", "unknown reason"),
    )

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

    if getattr(result, "output_limited", False):
        item["status"] = "failed"
        item["error"] = f"stage output reached {MAX_STAGE_OUTPUT_BYTES}-byte limit"
    if getattr(result, "cleanup_error", None):
        item["cleanup_error"] = result.cleanup_error

    if kind == "syn-scan":
        try:
            item["evidence"] = read_scan_evidence(result.stdout)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            item["status"] = "failed"
            item["evidence_error"] = str(exc)

    if kind == "http-probe" and result.returncode == 0:
        match = re.fullmatch(r"HTTP=([0-9]{3})\s*", result.stdout)
        if match is None or match.group(1) != "200":
            item["status"] = "failed"
            item["error"] = "client HTTP probe did not return exactly HTTP 200"

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
                for stream_name in ("stdout", "stderr"):
                    captured = getattr(exc, stream_name, None)
                    if captured:
                        if isinstance(captured, bytes):
                            captured = captured.decode("utf-8", "replace")
                        item[stream_name] = captured[-MAX_STAGE_OUTPUT_BYTES:]
                cleanup_error = getattr(exc, "cleanup_error", None)
                if cleanup_error:
                    item["cleanup_error"] = cleanup_error

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

        directory = ROOT / "reports" / "scenario-live"
        directory.mkdir(mode=0o700, exist_ok=True)
        directory_info = directory.lstat()
        require(
            stat.S_ISDIR(directory_info.st_mode)
            and directory_info.st_uid == os.geteuid()
            and not directory_info.st_mode & 0o077,
            "scenario evidence directory is not private to the operator",
        )

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
