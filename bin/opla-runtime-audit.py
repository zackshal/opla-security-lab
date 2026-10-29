#!/usr/bin/env python3
"""Create evidence-first OPLA runtime-readiness reports.

The default ``--static`` mode reads only the checkout.  ``--capture-live`` is
an *observation* tool for an explicitly authorised dedicated host: it neither
starts nor stops units, opens network connections, changes files, or promotes
the laboratory to READY.  It records a narrow process/FD/socket snapshot so a
subsequent P14--P21 review can use evidence rather than an ``active`` label.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
try:
    import resource
except ImportError:  # Keep static inventory importable on non-POSIX control planes.
    resource = None
import signal
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MAX_CAPTURE_BYTES = 256 * 1024
MAX_FDS = 4096
COMMAND_TIMEOUT_SECONDS = 5
COMMAND_REAP_TIMEOUT_SECONDS = 2
DIAGNOSTIC_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}
HOST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
LAB_UNIT_RE = re.compile(
    r"^(?:dhcp-lab-[A-Za-z0-9]{4,32}|qemu-lab-[A-Za-z0-9]{4,32}-(?:victim|attacker|client))\.service$")
SYSTEMD_PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "MainPID",
                      "ExecMainPID", "User", "Group", "ControlGroup")
MAX_SELECTED_UNITS = 8
ASCII_PID_RE = re.compile(r"^[0-9]+$")

# This is deliberately a source inventory, not a claim that any listed
# component has run.  Keep the owner and the independent observation required
# next to the real entry points to make unsupported claims easy to spot.
COMPONENTS = (
    {
        "id": "control-plane",
        "requirement": "P14--P21 operation admission and user interface",
        "entry_points": ("bin/opla-cli.py", "bin/opla-runtime-audit.py", "bin/opla-platform.py", "Makefile", "bin/lab-cli.py"),
        "configuration": ("docs/user-guide/commands.md",),
        "owner": "invoking user; root-owned state is read as data",
        "runtime_check": "CLI help, selected-lab state and an operation with its durable receipt",
    },
    {
        "id": "host-admission",
        "requirement": "Gate C dedicated-host capability admission before P14",
        "entry_points": ("bin/opla-host-admission.py", "bin/opla-platform.py", "bin/opla-cli.py"),
        "configuration": ("docs/host-admission.md", "docs/test-host-spec.md"),
        "owner": "dedicated-host operator; self-reported observations require independent review",
        "runtime_check": "fresh read-only export/import bound to an independently recorded machine ID",
    },
    {
        "id": "lifecycle-orchestrator",
        "requirement": "P14 durable create/configure/resume/stop sequencing",
        "entry_points": ("bin/opla-lab-orchestrator.py", "bin/lab-lifecycle.py", "bin/opla-lab-progress.py"),
        "configuration": ("docs/lifecycle-call-graph.md",),
        "owner": "root-owned lifecycle locks, registry and lab state",
        "runtime_check": "stage journal plus independent resource/probe evidence",
    },
    {
        "id": "images",
        "requirement": "P14 image preparation and role/hash verification",
        "entry_points": ("bin/prepare-image.sh", "bin/opla-image-verify.py"),
        "configuration": ("docs/test-host-spec.md",),
        "owner": "operator image cache and root-owned lab overlays",
        "runtime_check": "verified role images and qemu-img/guest boot evidence",
    },
    {
        "id": "qemu-kvm-qmp",
        "requirement": "P14 three-VM provisioning, QMP and shutdown",
        "entry_points": ("bin/create-lab.sh", "bin/qmp.py", "bin/vm-state.py", "bin/vm-disk.py"),
        "configuration": ("docs/test-host-spec.md",),
        "owner": "root-owned systemd units, QCOW2 overlays and QMP sockets",
        "runtime_check": "KVM admission, QEMU PID/QMP operation and clean stop/resume",
    },
    {
        "id": "network-management",
        "requirement": "P14 isolated data and management networking",
        "entry_points": ("bin/create-lab.sh", "bin/lib.sh", "bin/opla_network.py", "bin/lab-lifecycle.py", "bin/control.sh"),
        "configuration": ("docs/task-dual-nic-topology.md",),
        "owner": "root-owned bridge/TAP/nftables resources",
        "runtime_check": "bridge/TAP membership, nft policy and pinned-management SSH",
    },
    {
        "id": "xdp-ebpf",
        "requirement": "P15 build, verifier, attachment, maps and detach",
        "entry_points": ("xdp/xdp_ddos_protect.c", "bin/control.sh",
                         "bin/xdp-scan-policy.sh", "xdp/build.sh", "xdp/deploy.sh",
                         "xdp/load.sh", "xdp/unload.sh", "xdp/fingerprint.py",
                         "xdp/runtime-guard.py", "xdp/scan-policy.py"),
        "configuration": ("docs/user-guide/xdp.md", "xdp/README.md"),
        "owner": "victim guest kernel and XDP maps",
        "runtime_check": "BTF/capabilities, verifier output, interface attachment and program/map IDs, counters, policy update and ownership-aware detach",
    },
    {
        "id": "suricata-ids",
        "requirement": "P16 IDS configuration, alerts and EVE evidence",
        "entry_points": ("bin/suricata.sh", "bin/security-ids-test.sh",
                         "bin/opla-eve-correlator.py", "security/suricata/manage.py",
                         "security/suricata/runtime.py", "security/suricata/nft_policy.py"),
        "configuration": ("security/suricata/opla.rules", "security/suricata/ips.rules"),
        "owner": "victim guest Suricata service and EVE log",
        "runtime_check": "validated config, capture interface, test alert and EVE correlation",
    },
    {
        "id": "scenario-engine",
        "requirement": "P17 bounded approved scenario execution",
        "entry_points": ("bin/opla-scenario.py", "bin/opla-scenario-live.py", "bin/opla-scenario-runner.py", "bin/opla_process.py"),
        "configuration": ("scenarios/syn-scan-baseline.yaml",),
        "owner": "scenario report directory; guest actions via management SSH",
        "runtime_check": "bounded run, source/destination identity and cleanup evidence",
    },
    {
        "id": "telemetry-evidence",
        "requirement": "P18 telemetry correlation and evidence quality",
        "entry_points": ("bin/opla-incident-report.py", "bin/opla-experiment-bundle.py", "bin/opla-event-correlator.py"),
        "configuration": ("docs/task-client-coverage.md",),
        "owner": "experiment report directory and immutable input artifacts",
        "runtime_check": "time-bound client, XDP, scan and EVE records linked by identity",
    },
    {
        "id": "monitoring",
        "requirement": "P19 monitoring collection and Zabbix delivery",
        "entry_points": ("monitoring/manage.sh", "monitoring/bridge.py", "monitoring/setup.py", "bin/opla_process.py"),
        "configuration": ("monitoring/compose.yaml", "monitoring/policy.json"),
        "owner": "shared monitoring stack; per-lab collector state",
        "runtime_check": "container/unit state, listening endpoint, collector record and API delivery",
    },
    {
        "id": "user-deployment",
        "requirement": "P20 user-defined inventory validation and connectivity planning",
        "entry_points": ("bin/opla-deploy.py", "bin/opla-connectivity-check.py"),
        "configuration": ("docs/deployment.md",),
        "owner": "user-provided manifest and explicitly approved remote targets",
        "runtime_check": "validated manifest, pinned key and separately authorised connectivity check",
    },
    {
        "id": "cleanup-recovery",
        "requirement": "P21 ownership-aware recovery and cleanup",
        "entry_points": ("bin/opla-secure-lab-delete.py", "bin/opla-active-creation-recover.py", "bin/opla-offline-prune.py"),
        "configuration": ("docs/user-guide/active-creation-recovery.md",),
        "owner": "root-owned receipts, locks and lab resources",
        "runtime_check": "fault injection, reconciliation and post-cleanup resource inventory",
    },
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"not a regular source file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest()


def has_symlink_ancestor(path: Path, root: Path) -> bool:
    """Return true if path escapes a real checkout through any symlink."""
    cursor = Path(path).absolute()
    boundary = Path(root).absolute()
    while True:
        if cursor.is_symlink():
            return True
        if cursor == boundary:
            return False
        if cursor.parent == cursor:
            return True
        cursor = cursor.parent


def source_file(path: Path, root: Path) -> bool:
    """Require a real, regular source/configuration input; never hash a link."""
    try:
        info = Path(path).lstat()
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode) and not Path(path).is_symlink()
            and not has_symlink_ancestor(path, root))


def static_inventory(root: Path = ROOT) -> list[dict]:
    """Return the implementation graph without executing any entry point."""
    root = Path(root)
    records = []
    for component in COMPONENTS:
        required = component["entry_points"] + component["configuration"]
        missing = [relative for relative in required if not source_file(root / relative, root)]
        fingerprints = {
            relative: sha256_file(root / relative)
            for relative in required if relative not in missing
        }
        records.append({
            **component,
            "required_files": list(required),
            "source_sha256": fingerprints,
            "static_verdict": "PASS" if not missing else "BLOCKED",
            "runtime_verdict": "NOT TESTED" if not missing else "BLOCKED",
            "reason": "source/configuration inventory complete" if not missing
                      else "missing required source/configuration: " + ", ".join(missing),
        })
    return records


def read_limited(path: Path, limit: int = MAX_CAPTURE_BYTES) -> str:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("capture limit must be a positive integer")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"capture is not a regular file: {path}")
        if info.st_size > limit:
            raise ValueError(f"capture exceeds {limit} bytes: {path}")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError(f"capture exceeds {limit} bytes: {path}")
    return data.decode("utf-8", "replace")


def _fd_kind(target: str) -> str:
    if target.startswith("socket:["):
        return "socket"
    if target.startswith("pipe:["):
        return "pipe"
    if target.startswith("anon_inode:[eventfd]"):
        return "eventfd"
    if target.startswith("anon_inode:[eventpoll]"):
        return "epoll"
    if target.startswith("/dev/net/tun"):
        return "tun_tap"
    return "file_or_other"


def _status_kib(facts: dict, key: str) -> int | None:
    value = facts.get(key)
    if value is None:
        return None
    fields = value.split()
    if len(fields) != 2 or fields[1] != "kB" or not fields[0].isdecimal():
        raise ValueError(f"malformed process status memory field: {key}")
    return int(fields[0])


def _proc_identity(raw: str, expected_pid: int) -> tuple[int, int, int, int, int]:
    """Parse PID, PPID, starttime, and CPU ticks from Linux proc stat."""
    fields = raw.rsplit(")", 1)
    if len(fields) != 2 or not fields[0].startswith(f"{expected_pid} ("):
        raise ValueError(f"malformed or mismatched process stat for {expected_pid}")
    values = fields[1].strip().split()
    # Fields after comm begin at Linux stat field 3 (state). PPID is field 4,
    # utime/stime are 14/15 and starttime is field 22.
    if (len(values) < 20 or not values[1].isdecimal()
            or not values[11].isdecimal() or not values[12].isdecimal()
            or not values[19].isdecimal()):
        raise ValueError(f"malformed process identity fields for {expected_pid}")
    return expected_pid, int(values[1]), int(values[19]), int(values[11]), int(values[12])


def _key_value_numbers(path: Path, allowed: set[str]) -> dict:
    values = {}
    for line in read_limited(path).splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        raw = raw.strip()
        if key in allowed:
            if not raw.isdecimal():
                raise ValueError(f"malformed numeric process field {key}: {path}")
            values[key] = int(raw)
    return values


def process_snapshot(pid: int, *, proc_root: Path = Path("/proc")) -> dict:
    """Read bounded, non-secret process/FD evidence from a supplied procfs root."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("pid must be a positive integer")
    proc_root = Path(proc_root)
    try:
        root_info = proc_root.lstat()
    except OSError as exc:
        raise ValueError(f"proc root is unavailable: {exc}") from exc
    if not stat.S_ISDIR(root_info.st_mode) or proc_root.is_symlink():
        raise ValueError("proc root must be a real directory")
    directory = proc_root / str(pid)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"process is unavailable: {pid}")
    identity_before = _proc_identity(read_limited(directory / "stat"), pid)
    status = read_limited(directory / "status")
    facts = {}
    for line in status.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            facts[key] = value.strip()
    for key in ("Pid", "Name", "PPid", "Uid", "Gid", "Threads"):
        if key not in facts:
            raise ValueError(f"malformed process status for {pid}: {key}")
    if int(facts["Pid"]) != pid or int(facts["PPid"]) != identity_before[1]:
        raise ValueError(f"process identity changed while reading {pid}")
    fd_dir = directory / "fd"
    if not fd_dir.is_dir() or fd_dir.is_symlink():
        raise ValueError(f"fd directory is unavailable: {pid}")
    fdinfo_dir = directory / "fdinfo"
    if not fdinfo_dir.is_dir() or fdinfo_dir.is_symlink():
        raise ValueError(f"fdinfo directory is unavailable: {pid}")
    kinds = Counter()
    descriptors = []
    entries = []
    with os.scandir(fd_dir) as scan:
        for entry in scan:
            if not entry.name.isdecimal():
                raise ValueError(f"malformed fd entry for {pid}: {entry.name}")
            entries.append(Path(entry.path))
            if len(entries) > MAX_FDS:
                raise ValueError(f"process descriptor count exceeds {MAX_FDS}: {pid}")
    entries.sort(key=lambda item: int(item.name))
    fdinfo_fields = Counter()
    for entry in entries:
        if entry.is_symlink():
            try:
                target = os.readlink(entry)
            except OSError as exc:
                target = f"unreadable:{type(exc).__name__}"
        else:
            target = "non-symlink-fd-entry"
        kind = _fd_kind(target)
        kinds[kind] += 1
        # Targets can include private paths.  Preserve resource type and fd
        # number only; socket inode is not needed for this generic snapshot.
        descriptors.append({"fd": int(entry.name), "kind": kind})
        try:
            fdinfo = read_limited(fdinfo_dir / entry.name, 16 * 1024)
        except OSError as exc:
            raise ValueError(f"fdinfo is unavailable for {pid}/{entry.name}: {exc}") from exc
        for line in fdinfo.splitlines():
            if ":" in line:
                fdinfo_fields[line.split(":", 1)[0]] += 1
    limits = read_limited(directory / "limits")
    nofile = next((line.split() for line in limits.splitlines()
                   if line.startswith("Max open files")), None)
    io = _key_value_numbers(directory / "io", {"read_bytes", "write_bytes", "syscr", "syscw"})
    identity_after = _proc_identity(read_limited(directory / "stat"), pid)
    if identity_after[:3] != identity_before[:3]:
        raise ValueError(f"process exited or PID was reused while reading {pid}")
    return {
        "pid": pid,
        "name": facts["Name"],
        "ppid": int(facts["PPid"]),
        "uid": int(facts["Uid"].split()[0]),
        "gid": int(facts["Gid"].split()[0]),
        "threads": int(facts["Threads"]),
        "memory_kib": {"rss": _status_kib(facts, "VmRSS"),
                       "size": _status_kib(facts, "VmSize"),
                       "swap": _status_kib(facts, "VmSwap")},
        "cpu_ticks": {"user": identity_after[3], "system": identity_after[4]},
        "io_bytes": {"read": io.get("read_bytes"), "write": io.get("write_bytes")},
        "fd_count": len(descriptors),
        "fd_kinds": dict(sorted(kinds.items())),
        "fdinfo_fields": dict(sorted(fdinfo_fields.items())),
        "descriptors": descriptors,
        "rlimit_nofile": {"soft": nofile[-3], "hard": nofile[-2]} if nofile and len(nofile) >= 3 else None,
    }


def filesystem_snapshot(path: Path = Path("/")) -> dict:
    """Return aggregate filesystem capacity only; no directory walk is needed."""
    info = os.statvfs(path)
    block = info.f_frsize
    return {
        "path": str(path),
        "total_bytes": info.f_blocks * block,
        "available_bytes": info.f_bavail * block,
        "used_bytes": (info.f_blocks - info.f_bfree) * block,
    }


def vetted_command(name: str) -> str:
    """Avoid executing a user-controlled executable through PATH."""
    candidates = {"ss": ("/usr/sbin/ss", "/usr/bin/ss"),
                  "systemctl": ("/usr/bin/systemctl", "/bin/systemctl")}
    for candidate in candidates[name]:
        try:
            info = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022):
            return candidate
    raise ValueError(f"trusted diagnostic executable unavailable: {name}")


def bounded_diagnostic_runner(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess:
    """Run one owned process group with bounded wall time and output files."""
    if resource is None or os.name != "posix":
        raise ValueError("bounded host diagnostics require a POSIX runtime")

    def limit_output_file():
        maximum = MAX_CAPTURE_BYTES + 1
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=stdout_file, stderr=stderr_file,
            close_fds=True, start_new_session=True, env=DIAGNOSTIC_ENV,
            preexec_fn=limit_output_file,
        )
        timed_out = False
        cleanup_error = None
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as group_error:
                cleanup_error = f"process-group kill failed: {group_error}"
                try:
                    process.kill()
                except OSError as process_error:
                    cleanup_error += f"; process kill failed: {process_error}"
            try:
                returncode = process.wait(timeout=COMMAND_REAP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                returncode = 124
                detail = f"process was not reaped within {COMMAND_REAP_TIMEOUT_SECONDS}s after SIGKILL"
                cleanup_error = f"{cleanup_error}; {detail}" if cleanup_error else detail
        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(MAX_CAPTURE_BYTES + 1)
        stderr = stderr_file.read(MAX_CAPTURE_BYTES + 1)
    truncated = (stdout_size > MAX_CAPTURE_BYTES or stderr_size > MAX_CAPTURE_BYTES
                 or len(stdout) > MAX_CAPTURE_BYTES or len(stderr) > MAX_CAPTURE_BYTES)
    result = subprocess.CompletedProcess(argv, 124 if timed_out else returncode,
                                          stdout=stdout[:MAX_CAPTURE_BYTES].decode("utf-8", "replace"),
                                          stderr=stderr[:MAX_CAPTURE_BYTES].decode("utf-8", "replace"))
    result.timed_out = timed_out
    result.output_truncated = truncated
    result.cleanup_error = cleanup_error
    return result


def run_read_only(argv: list[str], *, runner=None) -> dict:
    """Bound a diagnostic command's duration, storage and retained output."""
    result = (bounded_diagnostic_runner(argv, timeout=COMMAND_TIMEOUT_SECONDS)
              if runner is None else
              runner(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     timeout=COMMAND_TIMEOUT_SECONDS, check=False))
    stdout = (result.stdout or "")[:MAX_CAPTURE_BYTES]
    stderr = (result.stderr or "")[:MAX_CAPTURE_BYTES]
    timed_out = bool(getattr(result, "timed_out", False))
    output_truncated = bool(getattr(result, "output_truncated", False))
    cleanup_error = getattr(result, "cleanup_error", None)
    verdict = "PASS" if (result.returncode == 0 and not timed_out
                          and not output_truncated and cleanup_error is None) else "BLOCKED"
    return {"argv": argv, "exit_status": result.returncode, "stdout": stdout,
            "stderr": stderr, "timed_out": timed_out, "output_truncated": output_truncated,
            "cleanup_error": cleanup_error,
            "verdict": verdict}


def observe_command(name: str, arguments: list[str], *, runner=None) -> dict:
    """Record unavailable tools, timeouts and dispatch errors as blocked evidence."""
    requested = [name, *arguments]
    try:
        executable = vetted_command(name)
        return run_read_only([executable, *arguments], runner=runner)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {"argv": requested, "exit_status": None, "stdout": "",
                "stderr": f"{type(exc).__name__}: {exc}", "timed_out": isinstance(exc, subprocess.TimeoutExpired),
                "output_truncated": False, "cleanup_error": None, "verdict": "BLOCKED"}


def parse_systemd_properties(output: str, expected_unit: str) -> dict:
    """Parse a bounded `systemctl show` response for one exact selected unit."""
    properties = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in SYSTEMD_PROPERTIES or key in properties:
            raise ValueError("malformed or duplicate systemd property output")
        properties[key] = value
    if set(properties) != set(SYSTEMD_PROPERTIES):
        raise ValueError("systemd unit properties are incomplete")
    if properties["Id"] != expected_unit or not ASCII_PID_RE.fullmatch(properties["MainPID"]):
        raise ValueError("systemd unit identity or MainPID is invalid")
    if not ASCII_PID_RE.fullmatch(properties["ExecMainPID"]):
        raise ValueError("systemd ExecMainPID is invalid")
    return properties


def observe_systemd_unit(unit: str, *, runner=None) -> dict:
    observed = observe_command(
        "systemctl", ["show", "--no-pager", "--property=" + ",".join(SYSTEMD_PROPERTIES), unit],
        runner=runner)
    if observed["verdict"] != "PASS":
        return {"unit": unit, "verdict": "BLOCKED", "reason": "systemctl show failed",
                "command": observed}
    try:
        properties = parse_systemd_properties(observed["stdout"], unit)
    except ValueError as exc:
        return {"unit": unit, "verdict": "BLOCKED", "reason": str(exc), "command": observed}
    return {"unit": unit, "verdict": "PASS", "properties": properties,
            "reason": "unit state observed", "command": observed}


def capture_live(host_id: str, pids: list[int], *, units: list[str] | None = None,
                 proc_root: Path = Path("/proc"), machine_id_path: Path = Path("/etc/machine-id"),
                 runner=None) -> dict:
    """Collect read-only host observations after caller binds an exact host ID."""
    if not HOST_ID_RE.fullmatch(host_id):
        raise ValueError("--authorized-host-id must be the exact 32-hex machine ID")
    units = [] if units is None else units
    if (not isinstance(pids, list)
            or any(isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 for pid in pids)):
        raise ValueError("--pid values must be positive integers")
    if len(set(pids)) != len(pids):
        raise ValueError("--pid values must be unique")
    if (not isinstance(units, list) or len(units) > MAX_SELECTED_UNITS
            or any(not isinstance(unit, str) or not LAB_UNIT_RE.fullmatch(unit) for unit in units)):
        raise ValueError("--unit must name up to eight launcher-format qemu/dhcp lab units")
    if len(set(units)) != len(units):
        raise ValueError("--unit values must be unique")
    if not pids and not units:
        raise ValueError("--capture-live requires at least one --pid or --unit")
    actual = read_limited(machine_id_path, 128).strip().lower()
    if actual != host_id:
        raise ValueError("authorized host ID does not match this machine")
    unit_observations = []
    selected_pids = list(pids)
    unit_pid = {}
    pid_units = {}
    for unit in units:
        first = observe_systemd_unit(unit, runner=runner)
        record = {"unit": unit, "initial": first, "final": None, "verdict": first["verdict"]}
        if first["verdict"] == "PASS":
            main_pid = int(first["properties"]["MainPID"])
            if main_pid > 0:
                unit_pid[unit] = main_pid
                pid_units.setdefault(main_pid, []).append(unit)
                selected_pids.append(main_pid)
            elif first["properties"]["ActiveState"] == "active":
                record["verdict"] = "BLOCKED"
                record["reason"] = "active unit has no MainPID"
        unit_observations.append(record)
    selected_pids = list(dict.fromkeys(selected_pids))
    processes = []
    process_observations = []
    for pid in selected_pids:
        try:
            process = process_snapshot(pid, proc_root=proc_root)
        except (OSError, ValueError) as exc:
            process_observations.append({"pid": pid, "exit_status": None,
                                         "verdict": "BLOCKED",
                                         "systemd_units": pid_units.get(pid, []),
                                         "reason": f"{type(exc).__name__}: {exc}"})
        else:
            processes.append(process)
            process_observations.append({"pid": pid, "exit_status": 0,
                                         "verdict": "PASS", "systemd_units": pid_units.get(pid, []),
                                         "reason": "snapshot collected"})
    selected = {item["pid"] for item in processes}
    for record in unit_observations:
        first = record["initial"]
        if first["verdict"] != "PASS" or record["verdict"] != "PASS":
            continue
        final = observe_systemd_unit(record["unit"], runner=runner)
        record["final"] = final
        pid = unit_pid.get(record["unit"])
        if final["verdict"] != "PASS" or final["properties"] != first["properties"]:
            record["verdict"] = "BLOCKED"
            record["reason"] = "unit state or identity changed during process capture"
            for observation in process_observations:
                if observation["pid"] == pid:
                    observation["verdict"] = "BLOCKED"
                    observation["reason"] = "unit changed during capture; process snapshot linkage is uncertain"
        elif pid is not None and pid not in selected:
            record["verdict"] = "BLOCKED"
            record["reason"] = "unit MainPID process snapshot failed"
        else:
            record["verdict"] = "PASS"
            record["reason"] = "unit identity and MainPID remained stable during process capture"
    try:
        filesystem = filesystem_snapshot()
        filesystem_observation = {"exit_status": 0, "verdict": "PASS", "reason": "filesystem capacity collected"}
    except OSError as exc:
        filesystem = None
        filesystem_observation = {"exit_status": None, "verdict": "BLOCKED",
                                  "reason": f"{type(exc).__name__}: {exc}"}
    return {
        "operator_authorization": "read-only dedicated-host observation acknowledged",
        "host_id": actual,
        "processes": processes,
        "process_observations": process_observations,
        "systemd_unit_observations": unit_observations,
        "process_tree": [{"pid": item["pid"], "ppid": item["ppid"],
                          "parent_in_selected_scope": item["ppid"] in selected}
                         for item in processes],
        "filesystem": filesystem,
        "filesystem_observation": filesystem_observation,
        "listening_sockets": observe_command("ss", ["-H", "-ltnup"], runner=runner),
        "systemd_units": observe_command("systemctl", ["list-units", "--all", "--plain", "--no-legend", "opla-*", "qemu-*", "dhcp-*"], runner=runner),
        "verdict": "NOT TESTED",
        "reason": "observation captured; per-component functional operations remain required",
    }


def build_report(*, root: Path = ROOT, live: dict | None = None, evidence_path: Path | None = None) -> dict:
    started = utc_now()
    components = static_inventory(root)
    static_failures = [item["id"] for item in components if item["static_verdict"] != "PASS"]
    checks = [{
        "component": item["id"], "requirement": item["requirement"],
        "environment": "static checkout", "host_id": None,
        "command": "opla system audit",
        "start_time": started, "end_time": utc_now(), "exit_status": 0 if item["static_verdict"] == "PASS" else 2,
        "expected": "all listed source and configuration files exist",
        "observed": item["reason"], "evidence_path": str(evidence_path) if evidence_path else None,
        "verdict": item["static_verdict"], "reason": item["reason"],
        "reviewer": "unreviewed",
    } for item in components]
    if live is not None:
        snapshot_check = {
            "component": "host-observation-report",
            "requirement": "Assemble read-only host observation evidence",
            "environment": "explicitly authorised dedicated host", "host_id": live["host_id"],
            "command": "opla-runtime-audit.py --capture-live",
            "start_time": started, "end_time": utc_now(),
            "expected": "observation report retains every successful and blocked probe",
            "observed": {"reason": live["reason"], "process_count": len(live["processes"])},
            "evidence_path": str(evidence_path) if evidence_path else None,
            "reason": "report assembly is complete; individual observations determine observation_status",
            "reviewer": "unreviewed",
        }
        diagnostic_statuses = []
        process_observations = live.get("process_observations")
        if not isinstance(process_observations, list):
            process_observations = []
            diagnostic_statuses.append("BLOCKED")
        for observation in process_observations:
            if not isinstance(observation, dict):
                observation = {"pid": None, "exit_status": None, "verdict": "BLOCKED",
                               "reason": "malformed process observation"}
            verdict = observation.get("verdict")
            if verdict not in {"PASS", "BLOCKED"}:
                verdict = "BLOCKED"
            diagnostic_statuses.append(verdict)
            checks.append({
                "component": "host-observation:process:" + str(observation.get("pid")),
                "requirement": "P14--P21 process and file-descriptor snapshot",
                "environment": "explicitly authorised dedicated host",
                "host_id": live["host_id"],
                "command": "read /proc/<pid>/status, fd, fdinfo, limits, stat and io",
                "start_time": started,
                "end_time": utc_now(),
                "exit_status": observation.get("exit_status"),
                "expected": "bounded process and file-descriptor snapshot is readable",
                "observed": {"pid": observation.get("pid"),
                             "systemd_units": observation.get("systemd_units", []),
                             "reason": observation.get("reason")},
                "evidence_path": str(evidence_path) if evidence_path else None,
                "verdict": verdict,
                "reason": observation.get("reason", "process snapshot failed"),
                "reviewer": "unreviewed",
            })
        filesystem_observation = live.get("filesystem_observation")
        if not isinstance(filesystem_observation, dict):
            filesystem_observation = {"exit_status": None, "verdict": "BLOCKED",
                                     "reason": "filesystem observation missing"}
        filesystem_verdict = filesystem_observation.get("verdict")
        if filesystem_verdict not in {"PASS", "BLOCKED"}:
            filesystem_verdict = "BLOCKED"
        diagnostic_statuses.append(filesystem_verdict)
        checks.append({
            "component": "host-observation:filesystem",
            "requirement": "P14--P21 filesystem capacity snapshot",
            "environment": "explicitly authorised dedicated host",
            "host_id": live["host_id"],
            "command": "statvfs /",
            "start_time": started,
            "end_time": utc_now(),
            "exit_status": filesystem_observation.get("exit_status"),
            "expected": "filesystem capacity is readable",
            "observed": {"filesystem": live.get("filesystem"),
                         "reason": filesystem_observation.get("reason")},
            "evidence_path": str(evidence_path) if evidence_path else None,
            "verdict": filesystem_verdict,
            "reason": filesystem_observation.get("reason", "filesystem snapshot failed"),
            "reviewer": "unreviewed",
        })
        unit_observations = live.get("systemd_unit_observations", [])
        if not isinstance(unit_observations, list):
            unit_observations = []
            diagnostic_statuses.append("BLOCKED")
        for unit_observation in unit_observations:
            if not isinstance(unit_observation, dict):
                diagnostic_statuses.append("BLOCKED")
                continue
            verdict = unit_observation.get("verdict")
            if verdict not in {"PASS", "BLOCKED"}:
                verdict = "BLOCKED"
            diagnostic_statuses.append(verdict)
            initial = unit_observation.get("initial", {})
            final = unit_observation.get("final") or {}
            checks.append({
                "component": "host-observation:systemd-unit:" + str(unit_observation.get("unit")),
                "requirement": "P14--P21 selected unit state and MainPID remain stable through process capture",
                "environment": "explicitly authorised dedicated host",
                "host_id": live["host_id"],
                "command": {"initial": initial.get("command", {}).get("argv", []),
                            "final": final.get("command", {}).get("argv", [])},
                "start_time": started,
                "end_time": utc_now(),
                "exit_status": (final.get("command", {}).get("exit_status")
                                if final else initial.get("command", {}).get("exit_status")),
                "expected": "exact selected unit identity and MainPID are stable around process/FD snapshot",
                "observed": {"unit": unit_observation.get("unit"),
                             "initial": initial.get("properties"),
                             "final": final.get("properties"),
                             "reason": unit_observation.get("reason")},
                "evidence_path": str(evidence_path) if evidence_path else None,
                "verdict": verdict,
                "reason": unit_observation.get("reason", "unit observation failed"),
                "reviewer": "unreviewed",
            })
        for key, requirement in (
                ("listening_sockets", "P14--P21 listening-socket inventory"),
                ("systemd_units", "P14--P21 unit inventory")):
            observation = live.get(key)
            if not isinstance(observation, dict):
                observation = {"argv": [], "exit_status": None, "stdout": "", "stderr": "",
                               "verdict": "BLOCKED"}
            verdict = observation.get("verdict")
            if verdict not in {"PASS", "BLOCKED"}:
                verdict = "BLOCKED"
            diagnostic_statuses.append(verdict)
            checks.append({
                "component": "host-observation:" + key,
                "requirement": requirement,
                "environment": "explicitly authorised dedicated host",
                "host_id": live["host_id"],
                "command": observation.get("argv", []),
                "start_time": started,
                "end_time": utc_now(),
                "exit_status": observation.get("exit_status"),
                "expected": "read-only diagnostic command exits successfully",
                "observed": {"stdout": observation.get("stdout", ""),
                             "stderr": observation.get("stderr", ""),
                             "timed_out": observation.get("timed_out", False),
                             "output_truncated": observation.get("output_truncated", False),
                             "cleanup_error": observation.get("cleanup_error")},
                "evidence_path": str(evidence_path) if evidence_path else None,
                "verdict": verdict,
                "reason": ("diagnostic completed" if verdict == "PASS" else
                           "diagnostic failed or returned an invalid result"),
                "reviewer": "unreviewed",
            })
        observation_status = "BLOCKED" if "BLOCKED" in diagnostic_statuses else "PASS"
        snapshot_check["exit_status"] = 0 if observation_status == "PASS" else 2
        snapshot_check["verdict"] = observation_status
        checks.append(snapshot_check)
    else:
        observation_status = "NOT TESTED"
    return {
        "schema_version": 1,
        "kind": "opla_runtime_readiness",
        "created_at": utc_now(),
        "mode": "dedicated-host-observation" if live is not None else "static",
        "execution_performed": live is not None,
        "host_mutated": False,
        "observation_status": observation_status,
        "overall_status": "BLOCKED" if static_failures else "NOT TESTED",
        "blockers": (["static inventory incomplete: " + ", ".join(static_failures)] if static_failures else
                     ["P14--P21 functional runtime verification has not been completed"]),
        "components": components,
        "checks": checks,
        "live_observation": live,
    }


def reject_symlink_ancestors(path: Path) -> None:
    """Keep explicit evidence writes inside real directories, without links."""
    cursor = Path(path).absolute()
    while True:
        if cursor.exists() and cursor.is_symlink():
            raise ValueError(f"unsafe symlink ancestor: {cursor}")
        if cursor.parent == cursor:
            return
        cursor = cursor.parent


def write_report(path: Path, report: dict) -> None:
    path = Path(path)
    reject_symlink_ancestors(path.parent)
    if not path.parent.is_dir():
        raise ValueError("evidence parent must already exist")
    if path.exists() or path.is_symlink():
        raise ValueError("refusing to overwrite or follow existing evidence path")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def verify_report(path: Path, *, root: Path = ROOT) -> dict:
    """Verify that a report is still bound to this source tree.

    This establishes source freshness only. It never upgrades P14--P21 runtime
    status, even when every fingerprint matches.
    """
    path = Path(path)
    reject_symlink_ancestors(path.parent)
    try:
        stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"evidence unavailable: {exc}") from exc
    if path.is_symlink() or not path.is_file() or stat.st_nlink != 1:
        raise ValueError("evidence must be a regular single-link file")
    if stat.st_mode & 0o022:
        raise ValueError("evidence must not be group/other writable")
    try:
        saved = json.loads(read_limited(path))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid evidence JSON: {exc}") from exc
    if not isinstance(saved, dict) or saved.get("kind") != "opla_runtime_readiness":
        raise ValueError("unexpected evidence kind")
    saved_components = saved.get("components")
    if not isinstance(saved_components, list):
        raise ValueError("evidence components missing")
    current_items = static_inventory(root)
    current = {item["id"]: item for item in current_items}
    observed = {}
    for item in saved_components:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("malformed evidence component")
        identifier = item["id"]
        if identifier in observed:
            raise ValueError("duplicate evidence component")
        observed[identifier] = item.get("source_sha256")
    if set(observed) != set(current):
        raise ValueError("evidence component set differs from current inventory")
    changed = [identifier for identifier, item in current.items() if observed[identifier] != item["source_sha256"]]
    expected = build_report(root=root)

    def parse_timestamp(value):
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else None

    def same_check(check, expected_check):
        if not isinstance(check, dict):
            return False
        stable = ("component", "requirement", "environment", "host_id", "command",
                  "exit_status", "expected", "observed", "verdict", "reason", "reviewer")
        if any(check.get(key) != expected_check.get(key) for key in stable):
            return False
        if check.get("reviewer") != "unreviewed":
            return False
        start = parse_timestamp(check.get("start_time"))
        end = parse_timestamp(check.get("end_time"))
        if start is None or end is None or end < start:
            return False
        evidence = check.get("evidence_path")
        return (isinstance(evidence, str)
                and Path(evidence).resolve(strict=False) == path.resolve())

    semantic_match = (
        saved.get("schema_version") == 1
        and parse_timestamp(saved.get("created_at")) is not None
        and saved.get("mode") == "static"
        and saved.get("execution_performed") is False
        and saved.get("host_mutated") is False
        and saved.get("observation_status") == "NOT TESTED"
        and saved.get("overall_status") == expected["overall_status"]
        # JSON turns source tuples into lists. Compare the canonical JSON form,
        # not Python's tuple/list representation.
        and json.dumps(saved_components, sort_keys=True, separators=(",", ":"))
            == json.dumps(current_items, sort_keys=True, separators=(",", ":"))
        and isinstance(saved.get("checks"), list)
        and len(saved["checks"]) == len(expected["checks"])
        and all(same_check(check, expected_check)
                for check, expected_check in zip(saved["checks"], expected["checks"]))
    )
    if not semantic_match:
        changed.append("report-semantics")
    return {
        "kind": "opla_runtime_readiness_verification",
        "evidence": str(path),
        "verification_status": "PASS" if not changed else "BLOCKED",
        "changed_components": changed,
        "runtime_status": saved.get("overall_status", "UNKNOWN"),
        "reason": "source fingerprints match; this is not live acceptance" if not changed
                  else "source fingerprints changed: " + ", ".join(changed),
    }


def read_evidence_object(path: Path) -> dict:
    """Load one bounded, private regular evidence record without following links."""
    path = Path(path)
    reject_symlink_ancestors(path.parent)
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError(f"evidence unavailable: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("evidence must be a regular single-link file")
    if info.st_mode & 0o022:
        raise ValueError("evidence must not be group/other writable")
    try:
        value = json.loads(read_limited(path))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid evidence JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("evidence must be a JSON object")
    return value


def compare_live_observations(baseline_path: Path, candidate_path: Path) -> dict:
    """Compare two captured snapshots without inferring a resource leak.

    The reports remain observations.  A reviewer needs workload context and a
    stabilization capture before deciding whether a persistent delta is bad.
    """
    baseline = read_evidence_object(baseline_path)
    candidate = read_evidence_object(candidate_path)

    def observation(report: dict, label: str) -> dict:
        if (report.get("kind") != "opla_runtime_readiness"
                or report.get("mode") != "dedicated-host-observation"
                or report.get("execution_performed") is not True
                or report.get("host_mutated") is not False):
            raise ValueError(f"{label} is not a read-only dedicated-host observation")
        live = report.get("live_observation")
        if not isinstance(live, dict) or not isinstance(live.get("host_id"), str):
            raise ValueError(f"{label} lacks host observation")
        processes = live.get("processes")
        if not isinstance(processes, list):
            raise ValueError(f"{label} lacks process list")
        indexed = {}
        for process in processes:
            if not isinstance(process, dict) or type(process.get("pid")) is not int:
                raise ValueError(f"{label} has malformed process")
            if process["pid"] in indexed:
                raise ValueError(f"{label} has duplicate process PID")
            indexed[process["pid"]] = process
        return {"host_id": live["host_id"], "processes": indexed,
                "filesystem": live.get("filesystem")}

    before = observation(baseline, "baseline")
    after = observation(candidate, "candidate")
    if before["host_id"] != after["host_id"]:
        raise ValueError("snapshots belong to different host IDs")
    common = sorted(set(before["processes"]) & set(after["processes"]))
    fields = ("threads", "fd_count", "memory_kib", "cpu_ticks", "io_bytes", "fd_kinds")
    changes = []
    for pid in common:
        old, new = before["processes"][pid], after["processes"][pid]
        changed = {key: {"before": old.get(key), "after": new.get(key)}
                   for key in fields if old.get(key) != new.get(key)}
        if changed:
            changes.append({"pid": pid, "name": new.get("name"), "changes": changed})
    return {
        "schema_version": 1,
        "kind": "opla_runtime_observation_comparison",
        "baseline": str(baseline_path),
        "candidate": str(candidate_path),
        "host_id": before["host_id"],
        "new_pids": sorted(set(after["processes"]) - set(before["processes"])),
        "exited_pids": sorted(set(before["processes"]) - set(after["processes"])),
        "process_changes": changes,
        "filesystem": {"before": before["filesystem"], "after": after["filesystem"]},
        "verdict": "NOT TESTED",
        "reason": "comparison is descriptive; use baseline/workload/cleanup/stabilization context before diagnosing a leak",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--static", action="store_true", help="Read only checkout files (default)")
    mode.add_argument("--capture-live", action="store_true", help="Read-only observation on an authorised dedicated host")
    mode.add_argument("--verify", type=Path, help="Verify source freshness of an existing report")
    mode.add_argument("--compare-baseline", type=Path, help="Compare a baseline dedicated-host observation")
    parser.add_argument("--compare-candidate", type=Path, help="Second observation for --compare-baseline")
    parser.add_argument("--authorized-host-id", help="Exact /etc/machine-id required for --capture-live")
    parser.add_argument("--i-accept-read-only-host-inspection", action="store_true")
    parser.add_argument("--pid", action="append", type=int, default=[], help="Process PID to snapshot; repeatable")
    parser.add_argument("--unit", action="append", default=[], help="Exact launcher-format qemu/dhcp lab unit (qemu roles: victim, attacker, client); repeatable")
    parser.add_argument("--output", type=Path, help="New JSON evidence path; never overwritten")
    args = parser.parse_args(argv)
    try:
        if args.verify:
            if args.compare_candidate:
                raise ValueError("--compare-candidate is valid only with --compare-baseline")
            result = verify_report(args.verify)
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result["verification_status"] == "PASS" else 2
        if args.compare_baseline:
            if not args.compare_candidate:
                raise ValueError("--compare-baseline requires --compare-candidate")
            if args.output:
                raise ValueError("comparison output is stdout; do not use --output")
            result = compare_live_observations(args.compare_baseline, args.compare_candidate)
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.compare_candidate:
            raise ValueError("--compare-candidate requires --compare-baseline")
        live = None
        if args.capture_live:
            if not args.i_accept_read_only_host_inspection or not args.authorized_host_id:
                raise ValueError("--capture-live requires explicit acknowledgement and --authorized-host-id")
            live = capture_live(args.authorized_host_id.lower(), args.pid, units=args.unit)
        report = build_report(live=live, evidence_path=args.output)
        if args.output:
            write_report(args.output, report)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 2 if (report["overall_status"] == "BLOCKED"
                     or report["observation_status"] == "BLOCKED") else 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: runtime audit: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
