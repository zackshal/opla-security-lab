#!/usr/bin/env python3
"""OPLA lab lifecycle receipts. Never deletes resources.

Records describe creation intent and successful lab setup, not proof of exclusive
ownership of kernel or Docker objects. Never authorize deletion from this data alone.
"""
import argparse
import ipaddress
import json
import os
import stat
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone

VALID = re.compile(r"lab-[A-Za-z0-9]{4,32}\Z")
BRIDGE = re.compile(r"br-op[0-9]+\Z")


def _trusted_file(path, label, *, private=False):
    """Validate evidence file identity before parsing untrusted contents."""
    path = Path(path)
    try:
        st = path.lstat()
    except OSError as exc:
        raise ValueError(f"unsafe or missing {label}") from exc
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
            or st.st_uid != os.getuid() or st.st_mode & 0o022
            or (private and st.st_mode & 0o077)):
        raise ValueError(f"unsafe {label} ownership or mode")
    return path


def state_of(root, labid, *, require_management=False):
    if not VALID.fullmatch(labid):
        raise ValueError("invalid lab ID")
    root = Path(root)
    lab = root / labid
    if lab.is_symlink() or not lab.is_dir():
        raise ValueError("lab missing or symlink")
    statefile = _trusted_file(lab / "state.env", "state.env")
    state = {}
    for line in statefile.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            state[key] = value
    if state.get("LAB_ID") != labid or not BRIDGE.fullmatch(state.get("BRIDGE", "")):
        raise ValueError("state identity mismatch")
    if "MGMT_BRIDGE" in state and (
            not BRIDGE.fullmatch(state.get("MGMT_BRIDGE", ""))
            or state.get("BRIDGE") == state.get("MGMT_BRIDGE")):
        raise ValueError("management bridge identity mismatch")
    mgmt_keys = ("MGMT_BRIDGE", "MGMT_SUBNET", "MGMT_GW", "ATTACKER_MGMT_IP",
                 "VICTIM_MGMT_IP", "CLIENT_MGMT_IP")
    if require_management and not all(key in state for key in mgmt_keys):
        raise ValueError("dual-NIC state required before registry ready")
    if any(key in state for key in mgmt_keys):
        if not all(key in state for key in mgmt_keys):
            raise ValueError("incomplete management state")
        data_net = ipaddress.ip_network(state.get("SUBNET", ""))
        mgmt_net = ipaddress.ip_network(state["MGMT_SUBNET"])
        if (data_net.prefixlen != 29 or mgmt_net.prefixlen != 29
                or not data_net.subnet_of(ipaddress.ip_network("100.64.0.0/10"))
                or not mgmt_net.subnet_of(ipaddress.ip_network("100.64.0.0/10"))
                or data_net.overlaps(mgmt_net)):
            raise ValueError("invalid or overlapping management subnet")
        for key in mgmt_keys[2:]:
            if ipaddress.ip_address(state[key]) not in mgmt_net:
                raise ValueError("management address outside subnet")
    return state


def receipt(root, labid, phase):
    state = state_of(root, labid, require_management=(phase == "ready"))
    bridge = state["BRIDGE"]
    n = bridge.removeprefix("br-op")
    entries = [
        {"kind": "lab_directory", "name": str(Path(root) / labid)},
        {"kind": "bridge", "name": bridge},
        {"kind": "nft_table", "name": "opla_" + labid.replace("-", "_")},
        {"kind": "dhcp_unit", "name": f"dhcp-{labid}.service"},
    ]
    for suffix in "avc":
        entries.append({"kind": "tap", "name": "op" + n + suffix})
    if "MGMT_BRIDGE" in state:
        mgmt_n = state["MGMT_BRIDGE"].removeprefix("br-op")
        entries.append({"kind": "management_bridge", "name": state["MGMT_BRIDGE"]})
        for suffix in "AVC":
            entries.append({"kind": "management_tap", "name": "op" + mgmt_n + suffix})
    for role in ("attacker", "victim", "client"):
        entries.extend([
            {"kind": "qemu_unit", "name": f"qemu-{labid}-{role}.service"},
            {"kind": "qcow2", "name": str(Path(root) / labid / role / "disk.qcow2")},
            {"kind": "cloud_init_iso", "name": str(Path(root) / labid / role / "seed.iso")},
        ])
    return {"schema": 1, "lab_id": labid, "lab_dir": str(Path(root) / labid),
            "phase": phase, "evidence": "created_by_opla", "resources": entries,
            "updated_utc": datetime.now(timezone.utc).isoformat()}


def persist(root, labid, phase):
    root = Path(root)
    data = receipt(root, labid, phase)
    regdir = root / "registry"
    if regdir.is_symlink():
        raise ValueError("registry path is symlink")
    regdir.mkdir(mode=0o700, exist_ok=True)
    regdir.chmod(0o700)
    target = regdir / f"{labid}.json"
    if target.is_symlink():
        raise ValueError("registry entry is symlink")
    if target.exists():
        old = json.loads(target.read_text(encoding="utf-8"))
        if old.get("lab_id") != labid or old.get("lab_dir") != str(root / labid):
            raise ValueError("registry identity mismatch")
    fd, tmp = tempfile.mkstemp(prefix=".receipt-", dir=regdir)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        dirfd = os.open(regdir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target


def inspect(root, labid=None):
    root = Path(root)
    regdir = root / "registry"
    if regdir.is_symlink():
        raise ValueError("registry directory is symlink")
    if not regdir.exists():
        return []
    results = []
    for path in sorted(regdir.glob("lab-*.json")):
        if labid and path.name != labid + ".json":
            continue
        try:
            _trusted_file(path, "registry receipt", private=True)
        except ValueError:
            results.append({"file": path.name, "status": "unsafe"})
            continue
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
            lab = path.stem
            if obj.get("schema") != 1 or obj.get("lab_id") != lab or obj.get("lab_dir") != str(root / lab):
                raise ValueError("identity mismatch")
            phase = obj.get("phase")
            state = state_of(root, lab, require_management=(phase == "ready"))
            expected = receipt(root, lab, phase)
            if obj.get("resources") != expected["resources"]:
                raise ValueError("receipt resources differ from state.env")
            status = "recorded" if phase == "ready" else "incomplete"
            # Only expose the validated, non-secret lab topology. Keep credentials,
            # evidence contents, and receipt internals inside the protected store.
            public_state = {
                key: state[key]
                for key in (
                    "LAB_ID", "BRIDGE", "SUBNET", "GW", "ATTACKER_IP",
                    "VICTIM_IP", "CLIENT_IP", "MGMT_BRIDGE", "MGMT_SUBNET",
                    "MGMT_GW", "ATTACKER_MGMT_IP", "VICTIM_MGMT_IP",
                    "CLIENT_MGMT_IP",
                )
                if key in state
            }
            results.append({"file": path.name, "lab": lab, "status": status,
                            "resources": len(obj["resources"]), "state": public_state})
        except (OSError, ValueError, UnicodeError, TypeError):
            results.append({"file": path.name, "status": "stale_or_invalid"})
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("begin", "ready", "list"))
    p.add_argument("--root", default="/var/lib/opla")
    p.add_argument("--lab")
    args = p.parse_args(argv)
    if args.action != "list" and not args.lab:
        p.error("--lab is required")
    if args.lab and not VALID.fullmatch(args.lab):
        p.error("invalid lab ID")
    if args.action == "list":
        results = inspect(args.root, args.lab)
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print(persist(args.root, args.lab, "creating" if args.action == "begin" else "ready"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f"OPLA registry: {exc}", file=sys.stderr)
        sys.exit(1)
