#!/usr/bin/env python3
"""OPLA lab lifecycle receipts. Never deletes resources.

Records describe creation intent and successful lab setup, not proof of exclusive
ownership of kernel or Docker objects. Never authorize deletion from this data alone.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone

VALID = re.compile(r"lab-[A-Za-z0-9]{4,32}\Z")
BRIDGE = re.compile(r"br-op[0-9]+\Z")


def state_of(root, labid):
    if not VALID.fullmatch(labid):
        raise ValueError("invalid lab ID")
    root = Path(root)
    lab = root / labid
    if lab.is_symlink() or not lab.is_dir():
        raise ValueError("lab missing or symlink")
    statefile = lab / "state.env"
    if statefile.is_symlink() or not statefile.is_file():
        raise ValueError("unsafe or missing state.env")
    state = {}
    for line in statefile.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            state[key] = value
    if state.get("LAB_ID") != labid or not BRIDGE.fullmatch(state.get("BRIDGE", "")):
        raise ValueError("state identity mismatch")
    return state


def receipt(root, labid, phase):
    state = state_of(root, labid)
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
        if path.is_symlink() or not path.is_file():
            results.append({"file": path.name, "status": "unsafe"})
            continue
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
            lab = path.stem
            if obj.get("schema") != 1 or obj.get("lab_id") != lab or obj.get("lab_dir") != str(root / lab):
                raise ValueError("identity mismatch")
            state_of(root, lab)
            status = "recorded" if obj.get("phase") == "ready" else "incomplete"
            results.append({"file": path.name, "lab": lab, "status": status,
                            "resources": len(obj.get("resources", []))})
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
