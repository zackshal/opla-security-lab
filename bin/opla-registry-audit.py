#!/usr/bin/env python3
"""Read-only cross-lab registry audit. A clean audit never authorizes deletion."""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("opla_registry_verify", HERE / "opla-registry-verify.py")
verify_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_mod)

RESOURCE_KINDS = frozenset({"lab_directory", "bridge", "management_bridge", "tap", "management_tap", "nft_table", "dhcp_unit", "qemu_unit", "qcow2", "cloud_init_iso"})


def audit(root, inspector=None):
    """Return report with read-only observations and hard errors.

    Registry receipts are user-controlled data for audit purposes, not authority
    to destroy host resources. Avoid following symlinks in every path checked.
    """
    root = Path(root)
    regdir = root / "registry"
    result = {"schema": 1, "root": str(root), "safe_for_deletion": False,
              "summary": {"receipts": 0, "errors": 0, "warnings": 0},
              "labs": [], "conflicts": [], "errors": []}
    if root.is_symlink() or regdir.is_symlink():
        result["errors"].append("root or registry is a symlink")
        result["summary"]["errors"] += 1
        return result
    if not regdir.exists():
        return result
    if not regdir.is_dir():
        result["errors"].append("registry is not a directory")
        result["summary"]["errors"] += 1
        return result
    # Verify all receipts together: a scoped audit could miss a collision.
    checks = verify_mod.verify(root, inspector=inspector or verify_mod.probe)
    names = {}
    for check in checks:
        labid = check["lab"]
        item = {"lab": labid, "status": check["status"],
                "errors": list(check["errors"]), "warnings": [],
                "resource_count": len(check["checks"])}
        result["labs"].append(item)
        result["summary"]["receipts"] += 1
        if check["status"] != "observed_unverified":
            item["warnings"].append("receipt not verifiable: no cleanup permitted")
        for resource in check["checks"]:
            key = (resource["kind"], resource["name"])
            if resource["kind"] not in RESOURCE_KINDS:
                item["errors"].append("unexpected resource kind")
            names.setdefault(key, set()).add(labid)
            if resource["kind"] in ("lab_directory", "qcow2", "cloud_init_iso"):
                path = Path(resource["name"])
                # Don't walk into symlinks, including any intermediate component.
                if root not in path.parents and path != root:
                    item["errors"].append("resource path escapes root")
                    continue
                for parent in (path, *list(path.parents)[:len(path.parts)]):
                    if parent == root.parent:
                        break
                    if parent.is_symlink():
                        item["errors"].append("symlink in managed resource path")
                        break
                if path.exists() and resource["kind"] != "lab_directory":
                    try:
                        mode = path.lstat().st_mode
                        if not stat.S_ISREG(mode) or path.stat().st_nlink != 1:
                            item["errors"].append("disk or seed is not an unlinked regular file")
                    except OSError:
                        item["errors"].append("unable to inspect disk or seed")
            if resource["status"] in ("unsafe", "unknown", "missing_or_unreadable", "inactive_or_unknown"):
                item["warnings"].append(resource["kind"] + ": " + resource["status"])
        result["summary"]["errors"] += len(item["errors"])
        result["summary"]["warnings"] += len(item["warnings"])
    for (kind, name), labs in sorted(names.items()):
        if len(labs) > 1:
            result["conflicts"].append({"kind": kind, "name": name, "labs": sorted(labs)})
    result["summary"]["errors"] += len(result["conflicts"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/var/lib/opla")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    data = audit(args.root)
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print("OPLA REGISTRY CROSS-LAB AUDIT — READ ONLY")
        print("Receipts:", data["summary"]["receipts"], "Errors:", data["summary"]["errors"])
        for lab in data["labs"]:
            print(f"{lab['lab']}: {lab['status']}, {lab['resource_count']} checks; errors={len(lab['errors'])}")
            for err in lab["errors"]:
                print("  BLOCKED:", err)
        for conflict in data["conflicts"]:
            print("  CONFLICT:", conflict)
        for err in data["errors"]:
            print("  BLOCKED:", err)
        print("Deletion is always blocked by this command. Inspect all records before changing cleanup behavior.")
    return 1 if data["summary"]["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
