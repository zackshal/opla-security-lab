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
import shlex
import shutil
import stat
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
MIN_MEM_AVAILABLE_KIB = 5120 * 1024
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


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
    seen: set[str] = set()
    invalid: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            key, separator, raw = line.partition("=")
            if not separator or key not in {"ID", "VERSION_ID"}:
                continue
            if key in seen:
                invalid.add(key)
                result.pop(key, None)
                continue
            seen.add(key)
            try:
                parsed = shlex.split(raw, comments=False, posix=True)
            except ValueError:
                invalid.add(key)
                continue
            if len(parsed) == 1 and parsed[0]:
                result[key] = parsed[0]
            else:
                invalid.add(key)
        for key in invalid:
            result.pop(key, None)
    except (OSError, UnicodeError):
        return result
    return result


def read_meminfo(path: Path = Path("/proc/meminfo")) -> dict[str, int]:
    """Read selected kernel memory facts as data, never by sourcing a file."""
    result: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition(":")
            if not separator or key not in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                continue
            fields = value.split()
            if len(fields) != 2 or fields[1] != "kB" or not fields[0].isdecimal():
                continue
            result[key] = int(fields[0])
    except (OSError, UnicodeError):
        return result
    return result


def storage_facts(path: Path = Path("/var/lib/opla")) -> dict[str, object]:
    """Measure the filesystem containing a prospective lab root, read-only."""
    requested = Path(path)
    probe = requested
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        info = os.statvfs(probe)
    except OSError as exc:
        return {"requested_path": str(requested), "probe_path": str(probe),
                "available": False, "reason": f"statvfs failed: {exc}"}
    block = info.f_frsize
    return {"requested_path": str(requested), "probe_path": str(probe), "available": True,
            "total_bytes": info.f_blocks * block,
            "available_bytes": info.f_bavail * block,
            "used_bytes": (info.f_blocks - info.f_bfree) * block,
            "reason": "measured capacity only; repository has no free-disk admission threshold"}


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


def trusted_tool_evidence(name: str) -> dict[str, str | None]:
    """Classify dependency visibility without conflating absence and uncertainty."""
    try:
        raw = shutil.which(name, path=SYSTEM_PATH)
        if not raw:
            return {"status": "ABSENT", "path": None, "reason": "not found on fixed system PATH"}
        path = Path(raw).resolve()
        roots = (Path("/usr/bin"), Path("/usr/sbin"), Path("/bin"), Path("/sbin"))
        if not any(path.is_relative_to(root) for root in roots):
            return {"status": "UNTRUSTED", "path": str(path), "reason": "resolved outside trusted system roots"}
        cursor = path
        while cursor != cursor.parent:
            info = cursor.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                return {"status": "UNTRUSTED", "path": str(path),
                        "reason": "path component is not root-owned or is group/other-writable"}
            cursor = cursor.parent
        return {"status": "PRESENT", "path": str(path), "reason": "trusted system executable"}
    except OSError:
        return {"status": "UNKNOWN", "path": None, "reason": "lookup or metadata inspection failed"}


def trusted_tool_path(name: str) -> Path | None:
    """Compatibility helper: return only a positively trusted executable."""
    evidence = trusted_tool_evidence(name)
    return Path(evidence["path"]) if evidence["status"] == "PRESENT" else None


def kvm_device_evidence(path: Path) -> dict[str, object]:
    """Inspect KVM visibility without turning permission errors into absence."""
    try:
        info = Path(path).stat()
    except FileNotFoundError:
        return {"status": "ABSENT", "read_write_access": False,
                "reason": "device path is absent in the current process view"}
    except OSError:
        return {"status": "UNKNOWN", "read_write_access": None,
                "reason": "device metadata inspection failed"}
    if not stat.S_ISCHR(info.st_mode):
        return {"status": "INVALID", "read_write_access": None,
                "reason": "device path exists but is not a character device"}
    try:
        accessible = os.access(path, os.R_OK | os.W_OK)
    except OSError:
        return {"status": "UNKNOWN", "read_write_access": None,
                "reason": "device access check failed"}
    if not accessible:
        return {"status": "INACCESSIBLE", "read_write_access": False,
                "reason": "not readable and writable by the current process identity"}
    return {"status": "PRESENT", "read_write_access": True,
            "reason": "device path visible and current process has read/write access"}


def inspect_capabilities(*, os_release: Path = Path("/etc/os-release"),
                         dev_kvm: Path = Path("/dev/kvm"),
                         meminfo: Path = Path("/proc/meminfo"),
                         storage_root: Path = Path("/var/lib/opla"),
                         required_tools=REQUIRED_HOST_TOOLS,
                         tool_resolver=None, tool_evidence_resolver=None,
                         kvm_evidence_resolver=kvm_device_evidence) -> dict:
    """Return capability evidence and fail-closed backend statuses.

    Only filesystem metadata and a trusted system-path lookup are used.  Presence of a device
    is not proof that KVM can launch guests; runtime validation remains a live
    gate on a dedicated host.
    """
    host = detect_host(os_release=os_release)
    if tool_resolver is not None and tool_evidence_resolver is not None:
        raise ValueError("provide only one tool resolver")
    tools = {}
    for name in required_tools:
        if tool_evidence_resolver is not None:
            evidence = dict(tool_evidence_resolver(name))
        elif tool_resolver is not None:
            # Older injected resolvers cannot distinguish absence from an
            # inspection failure. A returned path is evidence; None is UNKNOWN.
            path = tool_resolver(name)
            evidence = {"status": "PRESENT" if path is not None else "UNKNOWN",
                        "path": str(path) if path is not None else None,
                        "reason": "injected path resolver" if path is not None else "resolver returned no result"}
        else:
            evidence = trusted_tool_evidence(name)
        status = evidence.get("status")
        if status not in {"PRESENT", "ABSENT", "UNTRUSTED", "UNKNOWN"}:
            status = "UNKNOWN"
        available = (True if status == "PRESENT" else
                     False if status in {"ABSENT", "UNTRUSTED"} else None)
        tools[name] = {"available": available, "status": status,
                       "path": evidence.get("path"), "reason": evidence.get("reason", "")}
    linux = host["system"] == "linux"
    architecture_supported = host["machine"] == "x86_64"
    kvm = kvm_evidence_resolver(dev_kvm)
    kvm_present = (True if kvm["status"] in {"PRESENT", "INACCESSIBLE", "INVALID"} else
                   False if kvm["status"] == "ABSENT" else None)
    kvm_accessible = kvm["read_write_access"]
    unavailable = [name for name, data in tools.items() if data["status"] in {"ABSENT", "UNTRUSTED"}]
    uncertain_tools = [name for name, data in tools.items() if data["status"] == "UNKNOWN"]
    memory = read_meminfo(meminfo)
    memory_available = memory.get("MemAvailable")
    memory_ok = memory_available is not None and memory_available >= MIN_MEM_AVAILABLE_KIB
    storage = storage_facts(storage_root)

    control_plane = "FEASIBLE" if host["system"] in {"linux", "darwin", "windows"} else "UNKNOWN"
    supported_distribution = (host["distribution"].lower(), host["distribution_version"]) in {
        ("debian", "12"), ("debian", "13")}
    if not linux:
        vm_preflight = "BLOCKED"
        vm_reason = "existing backend requires Linux systemd, ip/nft, TAP and /dev/kvm"
    elif (not architecture_supported or unavailable
          or kvm["status"] in {"ABSENT", "INVALID"}
          or (memory_available is not None and not memory_ok)):
        vm_preflight = "BLOCKED"
        reasons = []
        if not architecture_supported:
            reasons.append(f"built-in QEMU/KVM template requires x86_64, got {host['machine']}")
        if unavailable:
            reasons.extend(f"{name}: {tools[name]['status'].lower()} ({tools[name]['reason']})"
                           for name in unavailable)
        if kvm["status"] == "ABSENT":
            reasons.append("/dev/kvm absent in the current process view")
        elif kvm["status"] == "INVALID":
            reasons.append("/dev/kvm path is not a character device")
        if memory_available is not None and not memory_ok:
            reasons.append(f"MemAvailable {memory_available} KiB below {MIN_MEM_AVAILABLE_KIB} KiB")
        vm_reason = "; ".join(reasons)
    elif (uncertain_tools or memory_available is None
          or kvm["status"] in {"UNKNOWN", "INACCESSIBLE"}):
        vm_preflight = "UNKNOWN"
        unknown = []
        if uncertain_tools:
            unknown.append("tool inspection unavailable: " + ", ".join(uncertain_tools))
        if memory_available is None:
            unknown.append("MemAvailable unavailable")
        if kvm["status"] in {"UNKNOWN", "INACCESSIBLE"}:
            unknown.append(f"/dev/kvm {str(kvm['status']).lower()}: {kvm['reason']}")
        vm_reason = "; ".join(unknown)
    elif not supported_distribution:
        vm_preflight = "UNKNOWN"
        vm_reason = (
            "no built-in host profile is validated for "
            f"{host['distribution']} {host['distribution_version']}; dependency presence alone is insufficient"
        )
    else:
        vm_preflight = "FEASIBLE"
        vm_reason = "Debian host profile prerequisites present; QEMU/KVM runtime is NOT TESTED"

    guest_preflight = "UNKNOWN"
    guest_reason = (
        "host inspection cannot establish guest runtime; measure guest kernel, "
        "BTF, bpftool, XDP driver, Suricata and scenario evidence inside the guest"
    )
    return {
        "schema_version": 1,
        "assessment_scope": "current process-visible environment; physical host status NOT TESTED",
        "host": host,
        "tools": tools,
        "kvm": {
            "path": str(dev_kvm),
            "present": kvm_present,
            "read_write_access": kvm_accessible,
            "status": kvm["status"],
            "reason": kvm["reason"],
        },
        "resources": {
            "memory": {"mem_available_kib": memory_available,
                       "minimum_preflight_kib": MIN_MEM_AVAILABLE_KIB,
                       "meets_create_preflight": memory_ok,
                       "raw": memory},
            "storage": storage,
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
