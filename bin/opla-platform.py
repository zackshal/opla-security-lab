#!/usr/bin/env python3
"""Read-only host platform and capability inspection for OPLA.

This module deliberately does not execute host utilities, change interfaces,
load kernels, or start virtual machines.  It reports prerequisites for the
existing Linux/QEMU backend and fails closed when a requested capability is
not established.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform as py_platform
import shutil
import sys


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_HOST_TOOLS = (
    "python3",
    "qemu-system-x86_64",
    "qemu-img",
    "cloud-localds",
    "dnsmasq",
    "ip",
    "nft",
    "flock",
    "systemd-run",
    "ssh",
)


def normalize_arch(value: str) -> str:
    """Return a stable architecture identifier without asserting support."""
    aliases = {
        "amd64": "x86_64",
        "x86-64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "riscv64": "riscv64",
    }
    return aliases.get(value.lower(), value.lower())


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Read os-release without sourcing or executing it."""
    result: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            result[key] = value.strip().strip('"')
    except (OSError, UnicodeError):
        return result
    return result


def detect_host(*, os_release: Path = Path("/etc/os-release")) -> dict:
    """Collect immutable host identity facts."""
    release = read_os_release(os_release)
    system = py_platform.system().lower()
    return {
        "system": system,
        "release": py_platform.release(),
        "machine": normalize_arch(py_platform.machine()),
        "python": py_platform.python_version(),
        "distribution": release.get("ID", "unknown"),
        "distribution_version": release.get("VERSION_ID", "unknown"),
    }


def _tool_report() -> dict[str, dict[str, object]]:
    report = {}
    for name in REQUIRED_HOST_TOOLS:
        resolved = shutil.which(name)
        report[name] = {"available": resolved is not None, "path": resolved}
    return report


def inspect_capabilities(*, os_release: Path = Path("/etc/os-release"),
                         dev_kvm: Path = Path("/dev/kvm"),
                         required_tools=REQUIRED_HOST_TOOLS) -> dict:
    """Return capability evidence and fail-closed backend statuses.

    Only filesystem metadata and PATH lookup are used.  Presence of a device
    is not proof that KVM can launch guests; runtime validation remains a live
    gate on a dedicated host.
    """
    host = detect_host(os_release=os_release)
    tools = {name: {
        "available": shutil.which(name) is not None,
        "path": shutil.which(name),
    } for name in required_tools}
    linux = host["system"] == "linux"
    kvm_present = dev_kvm.exists()
    kvm_accessible = os.access(dev_kvm, os.R_OK | os.W_OK)
    missing = [name for name, data in tools.items() if not data["available"]]

    control_plane = "FEASIBLE" if host["system"] in {"linux", "darwin", "windows"} else "UNKNOWN"
    if not linux:
        vm_preflight = "BLOCKED"
        vm_reason = "existing backend requires Linux systemd, ip/nft, TAP and /dev/kvm"
    elif missing or not kvm_present or not kvm_accessible:
        vm_preflight = "BLOCKED"
        reasons = []
        if missing:
            reasons.append("missing tools: " + ", ".join(missing))
        if not kvm_present:
            reasons.append("/dev/kvm absent")
        elif not kvm_accessible:
            reasons.append("/dev/kvm is not readable and writable")
        vm_reason = "; ".join(reasons)
    else:
        vm_preflight = "FEASIBLE"
        vm_reason = "prerequisites present; QEMU/KVM runtime is NOT TESTED"

    guest_preflight = "FEASIBLE" if linux else "BLOCKED"
    guest_reason = (
        "guest runtime is Linux-specific and requires independent guest kernel, "
        "BTF, bpftool, XDP driver and Suricata evidence"
        if linux else "XDP/eBPF and Suricata runtime are not provided by this host backend"
    )
    return {
        "schema_version": 1,
        "host": host,
        "tools": tools,
        "kvm": {
            "path": str(dev_kvm),
            "present": kvm_present,
            "read_write_access": kvm_accessible,
        },
        "capabilities": {
            "control_plane": {"status": control_plane, "preflight_status": control_plane,
                               "reason": "Python control and report processing only; runtime tests required"},
            "vm_hosting": {"status": "BLOCKED", "preflight_status": vm_preflight,
                           "reason": vm_reason},
            "guest_runtime": {"status": "BLOCKED", "preflight_status": guest_preflight,
                               "reason": guest_reason},
        },
        "execution": {
            "performed": False,
            "live_status": "NOT TESTED",
            "mutated_host": False,
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--require", choices=("control-plane", "vm-hosting", "guest-runtime"))
    args = parser.parse_args(argv)
    result = inspect_capabilities()
    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        host = result["host"]
        print(f"host={host['system']} arch={host['machine']} distro={host['distribution']}")
        for name, data in result["capabilities"].items():
            print(f"{name}: {data['status']} — {data['reason']}")
        print("live_status: NOT TESTED")
    if args.require:
        key = args.require.replace("-", "_")
        # Feasibility is only a descriptive preflight result. Admission requires
        # an independently captured runtime test and therefore accepts TESTED
        # only; this prevents /dev/kvm presence from becoming a false PASS.
        return 0 if result["capabilities"][key]["status"] == "TESTED" else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
