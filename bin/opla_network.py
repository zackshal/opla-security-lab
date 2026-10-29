#!/usr/bin/env python3
"""Select an unused OPLA /29 from the built-in IPv4 pool.

Selection is read-only. Both network creation paths use this implementation so
route destinations and gateways share the same exclusion rules.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import time


ADDRESS_POOL = ipaddress.ip_network("100.64.0.0/10")
LAB_PREFIX = 29
MAX_ROUTE_JSON_BYTES = 256 * 1024
PROCESS_CLEANUP_SECONDS = 1.0
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {"PATH": SYSTEM_PATH, "LC_ALL": "C", "LANG": "C"}
TRUSTED_ROOTS = tuple(Path(item) for item in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"))


def route_ipv4_networks(routes: object) -> list[ipaddress.IPv4Network]:
    """Return IPv4 route destinations and gateway host routes for conflict checks."""
    if not isinstance(routes, list):
        raise ValueError("route table must be a list")
    occupied: list[ipaddress.IPv4Network] = []
    for row in routes:
        if not isinstance(row, dict):
            raise ValueError("route row must be an object")
        destination = row["dst"] if "dst" in row else "default"
        if not isinstance(destination, str):
            raise ValueError("malformed route destination")
        if not destination:
            raise ValueError("malformed route destination")
        if destination != "default":
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except ValueError as exc:
                raise ValueError("malformed route destination") from exc
            if network.version == 4:
                occupied.append(network)
        gateway = row["gateway"] if "gateway" in row else None
        if "gateway" in row:
            if not isinstance(gateway, str):
                raise ValueError("malformed route gateway")
            try:
                address = ipaddress.ip_address(gateway)
            except ValueError as exc:
                raise ValueError("malformed route gateway") from exc
            if address.version == 4:
                occupied.append(ipaddress.ip_network(f"{address}/32"))
    return occupied


def select_free_subnet(routes: object, *, excluded: str | None = None,
                       reserved: object = ()) -> ipaddress.IPv4Network:
    """Pick the first unoccupied built-in subnet or fail closed."""
    occupied = route_ipv4_networks(routes)
    if not isinstance(reserved, (list, tuple)):
        raise ValueError("reserved subnet inventory must be a list")
    for raw in reserved:
        if not isinstance(raw, str):
            raise ValueError("malformed reserved subnet")
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise ValueError("malformed reserved subnet") from exc
        if (network.version != 4 or network.prefixlen != LAB_PREFIX
                or not network.subnet_of(ADDRESS_POOL)):
            raise ValueError("invalid reserved OPLA subnet")
        occupied.append(network)
    if excluded:
        try:
            excluded_network = ipaddress.ip_network(excluded, strict=False)
        except ValueError as exc:
            raise ValueError("malformed excluded subnet") from exc
        if excluded_network.version == 4:
            occupied.append(excluded_network)
    for subnet in ADDRESS_POOL.subnets(new_prefix=LAB_PREFIX):
        if not any(subnet.overlaps(existing) for existing in occupied):
            return subnet
    raise ValueError("no free /29 subnet in OPLA address pool")


def read_reserved_subnets(root: Path, *, expected_uid: int | None = None) -> list[str]:
    """Read retained lab network state, including stopped laboratories."""
    root = Path(root)
    expected_uid = os.geteuid() if expected_uid is None else expected_uid
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise ValueError("lab state root is unavailable") from exc
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != expected_uid
            or root_info.st_mode & 0o022):
        raise ValueError("unsafe lab state root for subnet allocation")
    reserved: list[str] = []
    for lab in sorted(root.glob("lab-*")):
        try:
            lab_info = lab.lstat()
        except OSError as exc:
            raise ValueError("lab inventory changed during subnet allocation") from exc
        if (not stat.S_ISDIR(lab_info.st_mode) or lab_info.st_uid != expected_uid
                or lab_info.st_mode & 0o022):
            raise ValueError("unsafe existing lab directory in subnet inventory")
        state = lab / "state.env"
        try:
            info = state.lstat()
        except FileNotFoundError:
            # A newly reserved empty directory has no network state yet.
            continue
        except OSError as exc:
            raise ValueError("cannot inspect existing lab state for subnet allocation") from exc
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != expected_uid or info.st_mode & 0o022
                or info.st_size > 64 * 1024):
            raise ValueError("unsafe existing lab state in subnet inventory")
        values: dict[str, str] = {}
        for line in state.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in {"LAB_ID", "SUBNET", "MGMT_SUBNET"}:
                if key in values:
                    raise ValueError("duplicate network key in existing lab state")
                values[key] = value
        if values.get("LAB_ID") != lab.name or "SUBNET" not in values:
            raise ValueError("incomplete existing lab network state")
        reserved.append(values["SUBNET"])
        if "MGMT_SUBNET" in values:
            reserved.append(values["MGMT_SUBNET"])
    return reserved


def trusted_ip_path() -> Path:
    """Resolve `ip` from fixed root-owned, non-writable system directories."""
    raw = shutil.which("ip", path=SYSTEM_PATH)
    if not raw:
        raise ValueError("trusted ip executable unavailable")
    path = Path(raw).resolve()
    if not any(path.is_relative_to(root) for root in TRUSTED_ROOTS):
        raise ValueError("ip executable is outside trusted system roots")
    cursor = path
    while cursor != cursor.parent:
        try:
            info = cursor.stat()
        except OSError as exc:
            raise ValueError("ip executable metadata unavailable") from exc
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("ip executable path is not trusted")
        cursor = cursor.parent
    return path


class DuplicateJSONKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError("route table JSON contains duplicate object key")
        result[key] = value
    return result


def _stop_owned_process(process) -> None:
    """Terminate and reap the process group created by our own Popen call."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        try:
            process.wait(timeout=PROCESS_CLEANUP_SECONDS)
        except (OSError, subprocess.SubprocessError):
            pass
        return
    except OSError:
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=PROCESS_CLEANUP_SECONDS)
            return
        except (OSError, subprocess.SubprocessError):
            pass
    deadline = time.monotonic() + PROCESS_CLEANUP_SECONDS
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        except OSError:
            break
        time.sleep(0.01)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
    try:
        process.wait(timeout=PROCESS_CLEANUP_SECONDS)
    except (OSError, subprocess.SubprocessError):
        pass


def _bounded_capture(argv, *, timeout: float, popen=subprocess.Popen) -> bytes:
    """Capture bounded stdout without buffering an untrusted child indefinitely."""
    process = popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
        env=SAFE_ENV, cwd="/",
    )
    assert process.stdout is not None
    output = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        eof = False
        while not eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            if not selector.select(remaining):
                raise subprocess.TimeoutExpired(argv, timeout)
            chunk = os.read(process.stdout.fileno(), min(65536, MAX_ROUTE_JSON_BYTES + 1 - len(output)))
            if not chunk:
                eof = True
                continue
            output.extend(chunk)
            if len(output) > MAX_ROUTE_JSON_BYTES:
                raise ValueError("route table output exceeds limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        returncode = process.wait(timeout=remaining)
        if returncode:
            raise subprocess.CalledProcessError(returncode, argv)
        return bytes(output)
    except (OSError, subprocess.SubprocessError, ValueError):
        _stop_owned_process(process)
        raise
    finally:
        selector.close()
        process.stdout.close()


def read_ipv4_routes(*, popen=subprocess.Popen) -> list[dict]:
    """Read a time- and size-bounded IPv4 route table via trusted `ip`."""
    argv = [str(trusted_ip_path()), "-j", "-4", "route", "show", "table", "all"]
    encoded = _bounded_capture(argv, timeout=4, popen=popen)
    try:
        routes = json.loads(encoded, object_pairs_hook=_reject_duplicate_keys)
    except DuplicateJSONKeyError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("route table JSON is malformed") from exc
    if not isinstance(routes, list):
        raise ValueError("route table JSON must contain a list")
    return routes


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exclude-subnet", help="also exclude this previously selected IPv4 subnet")
    parser.add_argument("--lab-root", type=Path, default=Path("/var/lib/opla"))
    args = parser.parse_args(argv)
    try:
        reserved = read_reserved_subnets(args.lab_root)
        subnet = select_free_subnet(read_ipv4_routes(), excluded=args.exclude_subnet,
                                    reserved=reserved)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"BLOCKED: subnet selection unavailable: {exc}", file=sys.stderr)
        return 2
    print(subnet.network_address)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
