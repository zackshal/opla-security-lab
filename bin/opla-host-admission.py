#!/usr/bin/env python3
"""Export or validate read-only OPLA host-admission evidence.

Collection runs only explicitly listed read-only probes. Import performs no
host commands. Missing visibility is UNKNOWN, never evidence of absence.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile

SCHEMA = 1
MAX_REPORT = 1024 * 1024
TOOLS = ("qemu-system-x86_64", "qemu-img", "cloud-localds", "dnsmasq", "ip", "nft", "flock", "python3", "systemd-run", "systemctl", "ssh", "suricata", "bpftool", "docker", "ss")
REQUIRED = {"cpu", "kvm", "memory", "filesystems", "network", "processes", "services", "listeners", "docker", "tools", "security"}
MIN_DISK_BYTES = 20 * 1024**3  # Planning margin, not a source-derived create requirement.
MACHINE_ID_HEX = set("0123456789abcdef")
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
PROBE_ENV = {"PATH": SYSTEM_PATH, "LC_ALL": "C", "LANG": "C"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_nonfinite_json(value):
    raise ValueError("non-finite JSON value")


def read_os_release(path=Path("/etc/os-release")):
    """Parse only ID and VERSION_ID as data; never source os-release."""
    values = {}
    seen = set()
    invalid = set()
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return values
    for line in lines:
        key, separator, raw = line.partition("=")
        if not separator or key not in {"ID", "VERSION_ID"}:
            continue
        if key in seen:
            invalid.add(key)
            values.pop(key, None)
            continue
        seen.add(key)
        try:
            parsed = shlex.split(raw, comments=False, posix=True)
        except ValueError:
            invalid.add(key)
            continue
        if len(parsed) == 1 and parsed[0]:
            values[key] = parsed[0]
        else:
            invalid.add(key)
    for key in invalid:
        values.pop(key, None)
    return values


def host_identity(*, os_release_path=Path("/etc/os-release")):
    try:
        machine = Path("/etc/machine-id").read_text().strip().lower()
    except OSError:
        machine = ""
    if len(machine) != 32 or any(ch not in "0123456789abcdef" for ch in machine):
        machine = None
    os_release = read_os_release(os_release_path)
    return {"machine_id": machine, "hostname": socket.gethostname(), "system": platform.system(),
            "release": platform.release(), "architecture": platform.machine(),
            "distribution_id": os_release.get("ID"),
            "distribution_version": os_release.get("VERSION_ID")}


def namespace_visibility():
    """Report namespace visibility without claiming this is bare metal."""
    compared = {}
    for name in ("mnt", "pid", "net", "user"):
        try:
            own = os.readlink(f"/proc/self/ns/{name}")
            init = os.readlink(f"/proc/1/ns/{name}")
            compared[name] = "SAME" if own == init else "DIFFERENT"
        except OSError:
            compared[name] = "UNKNOWN"
    if "DIFFERENT" in compared.values():
        visibility = "NAMESPACE_LIMITED"
    elif all(value == "SAME" for value in compared.values()):
        visibility = "PID1_NAMESPACE_MATCH"
    else:
        visibility = "UNKNOWN"
    # Matching PID 1 namespaces are only a visibility signal. They do not
    # attest physical hardware or prove that collection ran outside a sandbox.
    return {"visibility": visibility, "namespaces": compared,
            "physical_machine_type": "NOT TESTED"}


def collection_context():
    """Do not label privileged or non-interactive collection as a user terminal."""
    if os.getuid() != os.geteuid() or os.geteuid() == 0:
        return "privileged_or_setuid_terminal"
    return "user_terminal" if os.isatty(0) else "noninteractive_user_session"


def trusted_executable(name):
    """Resolve only a root-owned executable from the system search path."""
    try:
        raw = shutil.which(name, path=SYSTEM_PATH)
        if not raw:
            return None
        executable = Path(raw).resolve()
        if not any(executable.is_relative_to(root) for root in (Path("/usr/bin"), Path("/usr/sbin"), Path("/bin"), Path("/sbin"))):
            return None
        cursor = executable
        while cursor != cursor.parent:
            info = cursor.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                return None
            cursor = cursor.parent
        return executable
    except OSError:
        return None


def terminate_probe(process):
    """Best-effort kill and bounded reap for an owned diagnostic process."""
    failures = []
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        failures.append(f"killpg: {type(exc).__name__}")
        try:
            process.kill()
        except OSError as fallback:
            failures.append(f"kill: {type(fallback).__name__}")
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        failures.append("reap timeout")
    except OSError as exc:
        failures.append(f"wait: {type(exc).__name__}")
    return "; ".join(failures) or None


def probe(argv, timeout=4):
    process = None
    try:
        executable = trusted_executable(argv[0])
        if executable is None:
            return {"status": "UNKNOWN", "reason": "probe executable unavailable or untrusted"}
        def limit_output():
            resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.Popen([str(executable), *argv[1:]], stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, preexec_fn=limit_output,
                                       start_new_session=True, env=PROBE_ENV)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                cleanup = terminate_probe(process)
                result = {"status": "UNKNOWN", "reason": "probe timeout"}
                if cleanup:
                    result["cleanup_error"] = cleanup
                return result
            if out.tell() > 65536 or err.tell() > 4096:
                return {"status": "UNKNOWN", "reason": "probe output exceeds limit"}
            out.seek(0); err.seek(0)
            stdout = out.read().decode("utf-8", errors="replace")
            stderr = err.read().decode("utf-8", errors="replace")
        return {"status": "PRESENT" if code == 0 else "UNKNOWN",
                "exit_status": code, "stdout": stdout, "stderr": stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        result = {"status": "UNKNOWN", "reason": type(exc).__name__}
        if process is not None:
            cleanup = terminate_probe(process)
            if cleanup:
                result["cleanup_error"] = cleanup
        return result


def local_docker_socket_status(path=Path("/var/run/docker.sock")):
    """Classify only the local Docker endpoint; never consult remote contexts."""
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return "ABSENT"
    except OSError:
        return "UNKNOWN"
    return "PRESENT" if stat.S_ISSOCK(info.st_mode) else "UNKNOWN"


def docker_network_inventory(probe_runner=probe, socket_status=None):
    """Read local Docker IPAM data only; never inherit a remote context."""
    def scoped(result):
        result["inventory_scope"] = "canonical_rootful_socket_only"
        result["host_inventory_complete"] = False
        return result

    socket_status = local_docker_socket_status() if socket_status is None else socket_status
    if socket_status == "ABSENT":
        return scoped({"status": "UNKNOWN", "endpoint_status": "ABSENT",
                       "reason": "default local Docker socket is absent; configured networks were not inventoried"})
    if socket_status != "PRESENT":
        return scoped({"status": "UNKNOWN", "endpoint_status": socket_status,
                       "reason": "local Docker socket type or visibility is unknown"})
    docker_nets = probe_runner(["docker", "--host", "unix:///var/run/docker.sock", "network", "ls", "--quiet"])
    if docker_nets["status"] == "PRESENT":
        names = docker_nets.get("stdout", "").splitlines()
        if names:
            docker_nets = probe_runner(["docker", "--host", "unix:///var/run/docker.sock", "network", "inspect", *names,
                                        "--format", "{{json .IPAM.Config}}"])
            if docker_nets["status"] == "PRESENT":
                try:
                    docker_nets["stdout"] = json.dumps([entry for line in docker_nets["stdout"].splitlines()
                                                            for entry in json.loads(line)])
                except (ValueError, TypeError):
                    docker_nets = {"status": "UNKNOWN", "reason": "Docker subnet output malformed"}
        else:
            docker_nets["stdout"] = "[]"
    return scoped(docker_nets)


def tool_inventory(resolver=trusted_executable, ambient_lookup=shutil.which):
    """Distinguish absent tools from tools seen only in an untrusted PATH."""
    tools = {}
    for name in TOOLS:
        path = resolver(name)
        if path:
            tools[name] = {"status": "PRESENT", "path": str(path)}
        elif ambient_lookup(name):
            # It may exist in a user/admin PATH outside the reviewed roots;
            # that is not absence, but cannot establish trusted capability.
            tools[name] = {"status": "UNKNOWN", "path": None,
                           "reason": "tool found only outside trusted system path"}
        else:
            tools[name] = {"status": "ABSENT", "path": None}
    return tools


def collect(storage_root=Path("/var/lib/opla")):
    storage_root = Path(storage_root).absolute()
    mem = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, sep, tail = line.partition(":")
            fields = tail.split()
            if sep and key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} and len(fields) == 2 and fields[1] == "kB" and fields[0].isdigit():
                mem[key] = int(fields[0])
    except OSError:
        pass
    # Measure the selected existing path's mount without creating it.
    filesystems = probe(["df", "-PT", "-B1", "--", str(storage_root)])
    filesystems["requested_path"] = str(storage_root)
    routes = probe(["ip", "-j", "route", "show", "table", "all"])
    addresses = probe(["ip", "-j", "address", "show"])
    # An explicit local Unix socket plus scrubbed probe environment prevents an
    # operator's DOCKER_HOST/DOCKER_CONTEXT from inspecting a remote daemon.
    docker_nets = docker_network_inventory()
    listeners = probe(["ss", "-H", "-lntup"])
    services = probe(["systemctl", "list-units", "--type=service", "--state=running",
                      "--no-legend", "--no-pager"])
    kvm_path = Path("/dev/kvm")
    kvm_state = "UNKNOWN"
    try:
        info = kvm_path.stat()
        kvm_state = "PRESENT" if stat.S_ISCHR(info.st_mode) and os.access(kvm_path, os.R_OK | os.W_OK) else "UNKNOWN"
    except FileNotFoundError:
        kvm_state = "ABSENT"
    except OSError:
        pass
    try:
        cpu_count = os.cpu_count()
        cpuinfo = Path("/proc/cpuinfo").read_text(errors="replace")
        virtualization_flag = "vmx" if " vmx " in f" {cpuinfo} " else ("svm" if " svm " in f" {cpuinfo} " else None)
        virtualization_status = "PRESENT" if virtualization_flag else "ABSENT"
    except OSError:
        cpu_count, virtualization_flag, virtualization_status = None, None, "UNKNOWN"
    tools = tool_inventory()
    proc = probe(["ps", "-eo", "pid,ppid,user,stat,comm", "--no-headers"])
    security = {"uid": os.getuid(), "gid": os.getgid(), "effective_uid": os.geteuid(),
                "no_new_privs": None, "capabilities": "NOT TESTED"}
    try:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("NoNewPrivs:"):
                security["no_new_privs"] = line.split(":", 1)[1].strip() == "1"
    except OSError:
        pass
    try:
        exporter_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        exporter_sha256 = None
    return {"schema_version": SCHEMA, "kind": "opla_host_admission", "collected_at": utc_now(),
            "collector": {"name": "opla-host-admission", "source_sha256": exporter_sha256},
            "host": host_identity(),
            "collection_context": collection_context(),
            "read_only": True,
            "execution_scope": namespace_visibility(),
            "evidence": {
                "cpu": {"architecture": platform.machine(), "logical_cpus": cpu_count,
                        "virtualization_flag": virtualization_flag,
                        "virtualization_status": virtualization_status,
                        "status": "PRESENT" if cpu_count else "UNKNOWN"},
                "kvm": {"path": str(kvm_path), "status": kvm_state},
                "memory": {"values_kib": mem, "status": "PRESENT" if "MemAvailable" in mem else "UNKNOWN"},
                "filesystems": filesystems, "network": {"addresses": addresses, "routes": routes},
                "processes": proc, "services": services, "listeners": listeners,
                "docker": {"networks": docker_nets}, "tools": tools,
                "security": security,
            }}


def open_parent_directory(path):
    """Open every parent component without following a symlink at any depth."""
    absolute = os.path.abspath(os.fspath(path))
    parent, name = os.path.split(absolute)
    if not name or name in {".", ".."}:
        raise ValueError("report path must name a file")
    directory_flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                       | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    directory_fd = os.open("/", directory_flags)
    try:
        for component in parent.split(os.sep):
            if not component:
                continue
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd, name
    except OSError as exc:
        os.close(directory_fd)
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError("report path must not contain symlinks or non-directories") from None
        raise
    except BaseException:
        os.close(directory_fd)
        raise


def safe_read(path):
    directory_fd, name = open_parent_directory(path)
    # O_NONBLOCK prevents a caller-selected FIFO from hanging before fstat()
    # rejects non-regular input. It has no effect on ordinary regular files.
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        try:
            fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError("report path must not contain symlinks") from None
            raise
    finally:
        os.close(directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_REPORT:
            raise ValueError("report must be a bounded single-link regular file")
        chunks = []
        remaining = MAX_REPORT + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_REPORT:
            raise ValueError("report exceeds size limit")
        return raw
    finally:
        os.close(fd)


def write_new(path, data):
    """Write operator-selected evidence once, without following symlinks."""
    directory_fd, name = open_parent_directory(path)
    try:
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and stat.S_ISLNK(current.st_mode):
            raise ValueError("output path must not contain symlinks")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                     0o600, dir_fd=directory_fd)
        created = os.fstat(fd)
        if not stat.S_ISREG(created.st_mode):
            raise ValueError("output must be a regular file")
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            # The bytes were synced, but the directory entry may be ambiguous
            # after a crash.  Never delete a possibly persisted report.
            raise OSError("output contents synced but directory entry is not durable; reconcile manually") from exc
    except BaseException:
        # Never unlink a name after a failed create: even an inode check before
        # unlink has a rename race in a shared directory.  The O_EXCL result
        # may be partial, but it is safer to preserve it for reconciliation.
        raise
    finally:
        os.close(directory_fd)


def _validate_report(report, expected_host_id, raw=None, confirm_host_terminal=None,
                     expected_collector_sha256=None):
    if (not isinstance(expected_host_id, str) or len(expected_host_id) != 32
            or any(char not in MACHINE_ID_HEX for char in expected_host_id)):
        raise ValueError("expected host identity must be 32 lowercase hexadecimal characters")
    if (expected_collector_sha256 is not None and
            (not isinstance(expected_collector_sha256, str)
             or len(expected_collector_sha256) != 64
             or any(char not in "0123456789abcdef" for char in expected_collector_sha256))):
        raise ValueError("expected collector fingerprint must be 64 lowercase hexadecimal characters")
    if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
            or report.get("schema_version") != SCHEMA
            or report.get("kind") != "opla_host_admission"):
        raise ValueError("unsupported report schema")
    host, evidence = report.get("host"), report.get("evidence")
    collector = report.get("collector")
    scope = report.get("execution_scope")
    if not isinstance(host, dict) or not isinstance(evidence, dict):
        raise ValueError("report identity and evidence must be objects")
    missing_evidence = sorted(REQUIRED - evidence.keys())
    evidence = dict(evidence)
    for name in missing_evidence:
        evidence[name] = {}
    collector_valid = (
        isinstance(collector, dict)
        and collector.get("name") == "opla-host-admission"
        and isinstance(collector.get("source_sha256"), str)
        and len(collector["source_sha256"]) == 64
        and all(char in "0123456789abcdef" for char in collector["source_sha256"])
    )
    if not collector_valid:
        collector = {}
    if (expected_collector_sha256 is not None and collector_valid
            and collector["source_sha256"] != expected_collector_sha256):
        raise ValueError("collector fingerprint differs from independently pinned exporter")
    if not isinstance(scope, dict):
        scope = {}
    if (scope.get("visibility") not in
            {"NAMESPACE_LIMITED", "PID1_NAMESPACE_MATCH", "UNKNOWN"}
            or not isinstance(scope.get("namespaces"), dict)):
        scope = {"visibility": "UNKNOWN",
                 "namespaces": {name: "UNKNOWN" for name in ("mnt", "pid", "net", "user")},
                 "physical_machine_type": "NOT TESTED"}
    namespaces = scope["namespaces"]
    namespace_names = {"mnt", "pid", "net", "user"}
    if (not namespace_names <= namespaces.keys()
            or any(namespaces[name] not in {"SAME", "DIFFERENT", "UNKNOWN"}
                   for name in namespace_names)):
        scope = {"visibility": "UNKNOWN",
                 "namespaces": {name: "UNKNOWN" for name in namespace_names},
                 "physical_machine_type": "NOT TESTED"}
        namespaces = scope["namespaces"]
    expected_visibility = ("NAMESPACE_LIMITED" if "DIFFERENT" in namespaces.values() else
                           ("PID1_NAMESPACE_MATCH" if all(namespaces[n] == "SAME" for n in namespace_names)
                            else "UNKNOWN"))
    if scope["visibility"] != expected_visibility:
        raise ValueError("execution scope classification conflicts with namespace evidence")
    if scope.get("physical_machine_type", "NOT TESTED") != "NOT TESTED":
        raise ValueError("physical machine type must remain NOT TESTED")
    created = None
    try:
        timestamp = report.get("collected_at")
        if isinstance(timestamp, str):
            created = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        pass
    now = datetime.now(timezone.utc)
    timestamp_valid = created is not None and created.tzinfo is not None
    if timestamp_valid and (created > now or (now - created).total_seconds() > 7 * 86400):
        raise ValueError("collection timestamp is future or older than seven days")
    if not timestamp_valid:
        created = None
    machine_id = host.get("machine_id")
    identity_valid = (isinstance(machine_id, str) and len(machine_id) == 32
                      and not any(c not in MACHINE_ID_HEX for c in machine_id))
    if identity_valid and machine_id != expected_host_id:
        raise ValueError("host identity differs from independently recorded expected ID")
    if identity_valid and confirm_host_terminal is not None and confirm_host_terminal != machine_id:
        raise ValueError("host-terminal confirmation differs from report machine ID")
    security_identity = evidence["security"] if isinstance(evidence["security"], dict) else {}
    uid, effective_uid = security_identity.get("uid"), security_identity.get("effective_uid")
    verdicts = []
    if missing_evidence:
        verdicts.extend(f"UNKNOWN: required evidence section {name} missing" for name in missing_evidence)
    if not collector_valid:
        verdicts.append("UNKNOWN: collector provenance fields missing or invalid")
    if created is None:
        verdicts.append("UNKNOWN: collection timestamp missing or invalid")
    if not identity_valid:
        verdicts.append("UNKNOWN: host machine identity missing or invalid")
    if any(not isinstance(host.get(name), str) or not host.get(name)
           for name in ("hostname", "system", "release", "architecture")):
        verdicts.append("UNKNOWN: host descriptive identity incomplete")
    distribution = host.get("distribution_id")
    distribution_version = host.get("distribution_version")
    if not isinstance(distribution, str) or not distribution or not isinstance(distribution_version, str) or not distribution_version:
        verdicts.append("UNKNOWN: distribution identity or version unavailable")
    elif (distribution.lower(), distribution_version) not in {("debian", "12"), ("debian", "13")}:
        verdicts.append("UNKNOWN: this distribution/version has no validated built-in host profile")
    collection_valid = (report.get("read_only") is True
                        and report.get("collection_context") == "user_terminal"
                        and type(uid) is int and type(effective_uid) is int
                        and uid > 0 and effective_uid == uid)
    if not collection_valid:
        verdicts.append("UNKNOWN: ordinary user-terminal collection is not established")
    if scope.get("visibility") == "UNKNOWN":
        verdicts.append("UNKNOWN: execution namespace visibility unavailable")
    cpu = evidence["cpu"] if isinstance(evidence["cpu"], dict) else {}
    architecture = cpu.get("architecture")
    logical_cpus = cpu.get("logical_cpus")
    if not isinstance(architecture, str) or type(logical_cpus) is not int or logical_cpus <= 0:
        verdicts.append("UNKNOWN: CPU architecture or count unavailable")
    elif architecture != "x86_64":
        verdicts.append("BLOCKED: built-in QEMU template requires x86_64 host architecture")
    virtualization_status = cpu.get("virtualization_status")
    if virtualization_status == "ABSENT":
        verdicts.append("BLOCKED: CPU hardware virtualization flag is absent")
    elif virtualization_status != "PRESENT" or cpu.get("virtualization_flag") not in {"vmx", "svm"}:
        verdicts.append("UNKNOWN: CPU hardware virtualization capability unavailable")
    required_tools = ("qemu-system-x86_64", "qemu-img", "cloud-localds", "dnsmasq", "ip", "nft", "flock", "python3", "systemd-run", "systemctl", "ssh")
    tool_data = evidence["tools"] if isinstance(evidence["tools"], dict) else {}
    for name in required_tools:
        tool = tool_data.get(name, {})
        if not isinstance(tool, dict) or tool.get("status") not in {"PRESENT", "ABSENT"}:
            verdicts.append(f"UNKNOWN: tool {name} not measured")
        elif tool["status"] == "ABSENT":
            verdicts.append(f"BLOCKED: required tool {name} absent")
    if not isinstance(evidence["security"], dict) or type(evidence["security"].get("uid")) is not int:
        verdicts.append("UNKNOWN: security identity unavailable")
    for name in ("processes", "services", "listeners"):
        item = evidence.get(name, {})
        if not isinstance(item, dict) or item.get("status") != "PRESENT" or not isinstance(item.get("stdout"), str):
            verdicts.append(f"UNKNOWN: {name} inventory unavailable")
    processes = evidence.get("processes", {})
    if isinstance(processes, dict) and not processes.get("stdout", "").strip():
        verdicts.append("UNKNOWN: process inventory empty")
    kvm = evidence["kvm"].get("status") if isinstance(evidence["kvm"], dict) else "UNKNOWN"
    if kvm == "ABSENT": verdicts.append("BLOCKED: KVM device absent")
    elif kvm != "PRESENT": verdicts.append("UNKNOWN: KVM visibility not established")
    memory = evidence["memory"].get("values_kib", {}) if isinstance(evidence["memory"], dict) else {}
    available = memory.get("MemAvailable") if isinstance(memory, dict) else None
    if not isinstance(available, int) or isinstance(available, bool): verdicts.append("UNKNOWN: MemAvailable unavailable")
    elif available < 5120 * 1024: verdicts.append("BLOCKED: insufficient available RAM")
    fs = evidence["filesystems"] if isinstance(evidence["filesystems"], dict) else {}
    if fs.get("status") != "PRESENT":
        verdicts.append("UNKNOWN: filesystem capacity not visible")
    else:
        requested_path = fs.get("requested_path")
        if (not isinstance(requested_path, str) or not os.path.isabs(requested_path)
                or os.path.normpath(requested_path) != requested_path):
            verdicts.append("UNKNOWN: selected storage path is missing or invalid")
            requested_path = None
        # df -PT -B1 columns: Filesystem Type 1B-blocks Used Available Use% Mounted.
        rows = [line.split() for line in fs.get("stdout", "").splitlines() if line.strip()]
        candidates = [row for row in rows[1:] if len(row) >= 7]
        if requested_path is None:
            pass
        elif len(candidates) != 1:
            verdicts.append("UNKNOWN: expected one filesystem record for selected storage path")
        else:
            selected = candidates[0]
            available_disk = int(selected[4]) if selected[4].isdigit() else None
            if available_disk is None:
                verdicts.append("UNKNOWN: malformed filesystem capacity")
            elif available_disk < MIN_DISK_BYTES:
                verdicts.append("BLOCKED: less than 20 GiB available for images, overlays and evidence")
    net = evidence["network"] if isinstance(evidence["network"], dict) else {}
    routes = net.get("routes", {})
    addresses = net.get("addresses", {})
    docker = evidence["docker"].get("networks", {}) if isinstance(evidence["docker"], dict) else {}
    docker_status = docker.get("status") if isinstance(docker, dict) else "UNKNOWN"
    if (not isinstance(routes, dict) or not isinstance(addresses, dict)
            or routes.get("status") != "PRESENT" or addresses.get("status") != "PRESENT"):
        verdicts.append("UNKNOWN: route or address inventory incomplete")
    else:
        ranges = []
        parsed_sets = []
        inventories = [("routes", routes.get("stdout", "")),
                       ("addresses", addresses.get("stdout", "")),
                       ("Docker", docker.get("stdout", ""))]
        for source, blob in inventories:
            try:
                parsed = json.loads(blob, object_pairs_hook=unique_json_object,
                                    parse_constant=reject_nonfinite_json)
            except (TypeError, ValueError):
                verdicts.append("UNKNOWN: network or Docker CIDR data malformed")
                continue
            if not isinstance(parsed, list):
                verdicts.append("UNKNOWN: network or Docker CIDR data malformed")
                continue
            parsed_sets.append((source, parsed))
            for row in parsed:
                if not isinstance(row, dict):
                    verdicts.append("UNKNOWN: network or Docker CIDR data malformed")
                    continue
                if source == "addresses":
                    addr_info = row.get("addr_info")
                    if not isinstance(addr_info, list):
                        verdicts.append("UNKNOWN: malformed IPv4 address evidence")
                        continue
                    for addr in addr_info:
                        if not isinstance(addr, dict):
                            verdicts.append("UNKNOWN: malformed IPv4 address evidence")
                            continue
                        if addr.get("family") == "inet":
                            local, prefix = addr.get("local"), addr.get("prefixlen")
                            if not isinstance(local, str) or type(prefix) is not int:
                                verdicts.append("UNKNOWN: malformed IPv4 address evidence")
                                continue
                            try:
                                ranges.append(ipaddress.ip_network(f"{local}/{prefix}", strict=False))
                            except ValueError:
                                verdicts.append("UNKNOWN: malformed IPv4 address evidence")
                    continue
                token = row.get("dst" if source == "routes" else "Subnet")
                if not isinstance(token, str):
                    verdicts.append("UNKNOWN: network or Docker CIDR data malformed")
                elif token != "default":
                    try:
                        network = ipaddress.ip_network(token, strict=False)
                    except ValueError:
                        verdicts.append("UNKNOWN: network or Docker CIDR data malformed")
                    else:
                        if network.version == 4:
                            ranges.append(network)
                if source == "routes" and "gateway" in row:
                    gateways = [row.get("gateway")]
                else:
                    gateways = []
                if source == "routes" and "nexthops" in row:
                    nexthops = row.get("nexthops")
                    if not isinstance(nexthops, list) or not nexthops:
                        verdicts.append("UNKNOWN: malformed multipath route evidence")
                    else:
                        for nexthop in nexthops:
                            if not isinstance(nexthop, dict):
                                verdicts.append("UNKNOWN: malformed multipath route evidence")
                                continue
                            if "gateway" in nexthop:
                                gateways.append(nexthop.get("gateway"))
                for gateway in gateways:
                    if not isinstance(gateway, str):
                        verdicts.append("UNKNOWN: malformed route gateway evidence")
                        continue
                    try:
                        gateway_address = ipaddress.ip_address(gateway)
                    except ValueError:
                        verdicts.append("UNKNOWN: malformed route gateway evidence")
                    else:
                        if gateway_address.version == 4:
                            ranges.append(ipaddress.ip_network(f"{gateway_address}/32"))
        if any(source in {"routes", "addresses"} and not entries for source, entries in parsed_sets):
            verdicts.append("UNKNOWN: no usable route or address inventory")
        lab_range = ipaddress.ip_network("100.64.0.0/10")
        if any(item.overlaps(lab_range) for item in ranges):
            verdicts.append("BLOCKED: existing route or Docker network overlaps built-in OPLA address pool")
    if (docker_status != "PRESENT"
            or not isinstance(docker, dict)
            or docker.get("host_inventory_complete") is not True):
        verdicts.append("UNKNOWN: Docker inventory does not cover all host endpoints")
    scope_name = scope.get("visibility") if isinstance(scope, dict) else "UNKNOWN"
    sandbox_status = "REJECTED" if any(v.startswith("BLOCKED") for v in verdicts) else (
        "CONDITIONALLY ADMITTED" if not verdicts else "UNKNOWN")
    if scope_name == "NAMESPACE_LIMITED":
        host_status = "NOT TESTED"
        verdicts.append("UNKNOWN: collection has limited namespace visibility; host capabilities are not established")
    elif (scope_name == "PID1_NAMESPACE_MATCH"
          and confirm_host_terminal == machine_id
          and expected_collector_sha256 is not None
          and collector_valid
          and collector["source_sha256"] == expected_collector_sha256
          and identity_valid and timestamp_valid and collection_valid):
        host_status = sandbox_status
    else:
        host_status = "NOT TESTED"
        if scope_name != "PID1_NAMESPACE_MATCH":
            verdicts.append("UNKNOWN: execution scope does not establish host visibility")
        if confirm_host_terminal != machine_id:
            verdicts.append("UNKNOWN: host-terminal identity confirmation is missing")
        if expected_collector_sha256 is None:
            verdicts.append("UNKNOWN: independently pinned collector fingerprint is missing")
    return {"status": host_status, "sandbox_capability_assessment": sandbox_status,
            "host_assessment": host_status, "assessment_subject": "operator-attested-host-environment",
            "physical_machine_type": "NOT TESTED", "resource_controls": "NOT TESTED: cgroup, seccomp and service-unit limits",
            "execution_scope": scope, "host": host,
            "collected_at": report.get("collected_at"), "reasons": verdicts or ["minimum admission fields observed; further conflict and disk review required"],
            "source_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            "provenance": {
                "collector_fingerprint": (
                    "MATCHED_INDEPENDENT_PIN"
                    if collector_valid and expected_collector_sha256 == collector.get("source_sha256")
                    else "NOT TESTED"
                ),
                "collector_sha256": collector.get("source_sha256"),
                "expected_collector_sha256": expected_collector_sha256,
                "report_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
                "authenticity": "UNAUTHENTICATED_OPERATOR_SUPPLIED_EVIDENCE",
                "limitations": "fingerprint match identifies expected source bytes only; it does not prove who ran the exporter or prevent report fabrication",
            },
            "evidence": evidence}


def validate(report, expected_host_id, raw=None, confirm_host_terminal=None,
             expected_collector_sha256=None):
    """Validate untrusted imported JSON without leaking parser exceptions."""
    try:
        return _validate_report(report, expected_host_id, raw, confirm_host_terminal,
                                expected_collector_sha256)
    except (AttributeError, IndexError, OverflowError, RecursionError, TypeError) as exc:
        # Imported evidence is untrusted.  Malformed field types must produce a
        # stable fail-closed result instead of a traceback or accidental PASS.
        raise ValueError("report evidence has invalid field types") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    exp = actions.add_parser("export", help="collect read-only probes in this user session")
    exp.add_argument("--output", required=True, type=Path)
    exp.add_argument("--storage-root", type=Path, default=Path("/var/lib/opla"),
                     help="existing prospective data path whose filesystem is measured")
    imp = actions.add_parser("import", help="classify an existing JSON export; runs no host commands")
    imp.add_argument("report", type=Path)
    imp.add_argument("--expected-host-id", required=True, help="32-hex ID recorded independently by the operator")
    imp.add_argument("--expected-collector-sha256", required=True,
                     help="64-hex exporter fingerprint obtained independently from the reviewed exporter copy")
    imp.add_argument("--confirm-host-terminal", help="repeat the host machine ID to attest this export came from its ordinary user terminal")
    imp.add_argument("--output", type=Path, help="new decision JSON; never overwrites an existing file")
    args = parser.parse_args(argv)
    try:
        if args.action == "export":
            report = collect(args.storage_root)
            data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
            write_new(args.output, data)
            print(f"Exported read-only host observations: {args.output}")
            return 0
        raw = safe_read(args.report)
        report = json.loads(raw, object_pairs_hook=unique_json_object,
                            parse_constant=reject_nonfinite_json)
        result = validate(report, args.expected_host_id, raw, args.confirm_host_terminal,
                          args.expected_collector_sha256)
        if args.output:
            write_new(args.output, (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, RecursionError, json.JSONDecodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
