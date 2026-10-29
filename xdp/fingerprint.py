#!/usr/bin/env python3
"""Build and runtime fingerprints for OPLA XDP experiments."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BUILD_DIR = Path("/tmp/xdp-build")
OBJECT = BUILD_DIR / "xdp_ddos_protect.o"
SOURCE = BUILD_DIR / "xdp_ddos_protect.c"
MANIFEST = BUILD_DIR / "build-manifest.json"
LOAD_RECEIPT = BUILD_DIR / "load-receipt.json"
MAP_PIN_ROOT = Path("/sys/fs/bpf/opla/maps")
MAP_NAMES = ("syn_windows", "xdp_stats", "xdp_policy")
LOAD_RECEIPT_SCHEMA = 2


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def run_json(*args):
    return json.loads(
        subprocess.check_output(
            args, text=True, timeout=10
        )
    )


def write_manifest(data, destination=None):
    destination = MANIFEST if destination is None else Path(destination)
    temp = destination.with_name(
        f"{destination.name}.{os.getpid()}.tmp"
    )
    try:
        fd = os.open(
            temp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, destination)
    finally:
        temp.unlink(missing_ok=True)


def build(args):
    if not OBJECT.is_file() or not SOURCE.is_file():
        raise ValueError("BPF object or source is missing")

    compiler = subprocess.check_output(
        ["clang", "--version"], text=True, timeout=5
    ).splitlines()[0]

    manifest = {
        "schema_version": 1,
        "created_at": timestamp(),
        "compiler": compiler,
        "threshold": args.threshold,
        "window_ns": args.window_ns,
        "max_sources": args.max_sources,
        "source_sha256": sha256(SOURCE),
        "object_sha256": sha256(OBJECT),
    }

    write_manifest(manifest)
    print(json.dumps(manifest, indent=2))



def verified_build():
    if MANIFEST.is_symlink() or OBJECT.is_symlink() or SOURCE.is_symlink():
        raise ValueError("unsafe build artifacts")
    if not MANIFEST.is_file() or not OBJECT.is_file() or not SOURCE.is_file():
        raise ValueError("build manifest, source or BPF object missing")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("invalid build manifest")

    source_digest = manifest.get("source_sha256")
    if not isinstance(source_digest, str) or len(source_digest) != 64:
        raise ValueError("source fingerprint missing or invalid")
    if sha256(SOURCE) != source_digest:
        raise ValueError("source differs from build manifest")

    if sha256(OBJECT) != manifest.get("object_sha256"):
        raise ValueError("BPF object differs from build manifest")

    return manifest


def pinned_program():
    program = run_json(
        "bpftool", "-j", "prog", "show", "pinned",
        "/sys/fs/bpf/opla/program",
    )
    if isinstance(program, list):
        if len(program) != 1:
            raise ValueError("unexpected pinned program count")
        program = program[0]

    program_id = program.get("id")
    tag = program.get("tag")
    map_ids = program.get("map_ids")
    if type(program_id) is not int or not isinstance(tag, str) or not tag:
        raise ValueError("incomplete BPF program identity")
    if (not isinstance(map_ids, list) or not map_ids
            or any(type(map_id) is not int or map_id <= 0 for map_id in map_ids)
            or len(set(map_ids)) != len(map_ids)):
        raise ValueError("incomplete BPF program map identity")

    return {"program_id": program_id, "program_tag": tag,
            "program_map_ids": sorted(map_ids)}


def pinned_maps():
    maps = {}
    identifiers = set()
    for name in MAP_NAMES:
        result = run_json("bpftool", "-j", "map", "show", "pinned",
                          str(MAP_PIN_ROOT / name))
        if isinstance(result, list):
            if len(result) != 1:
                raise ValueError(f"unexpected pinned map count: {name}")
            result = result[0]
        if not isinstance(result, dict):
            raise ValueError(f"incomplete pinned map identity: {name}")
        map_id, map_type = result.get("id"), result.get("type")
        if type(map_id) is not int or map_id <= 0 or not isinstance(map_type, str) or not map_type:
            raise ValueError(f"incomplete pinned map identity: {name}")
        if map_id in identifiers:
            raise ValueError("duplicate pinned map identity")
        identifiers.add(map_id)
        maps[name] = {"id": map_id, "type": map_type}
    return maps


def validate_program_maps(program_identity, maps):
    if (not isinstance(program_identity, dict)
            or not isinstance(program_identity.get("program_map_ids"), list)
            or not isinstance(maps, dict) or set(maps) != set(MAP_NAMES)):
        raise ValueError("incomplete OPLA program/map identity")
    map_ids = [entry.get("id") if isinstance(entry, dict) else None
               for entry in maps.values()]
    program_ids = program_identity["program_map_ids"]
    if (any(type(item) is not int or item <= 0 for item in map_ids)
            or any(type(item) is not int or item <= 0 for item in program_ids)
            or len(set(program_ids)) != len(program_ids)
            or set(map_ids) != set(program_ids)):
        raise ValueError("pinned map IDs do not match maps referenced by OPLA program")


def record_load():
    manifest = verified_build()

    sys.path.insert(0, str(BUILD_DIR))
    import collect

    snapshot = collect.snapshot()
    if snapshot["loaded"] != 1:
        raise ValueError("BPF program is not attached")

    identity = pinned_program()
    maps = pinned_maps()
    validate_program_maps(identity, maps)
    receipt = {
        "schema_version": LOAD_RECEIPT_SCHEMA,
        "loaded_at": timestamp(),
        "attachment_mode": snapshot["mode"],
        "object_sha256": manifest["object_sha256"],
        "build_manifest_sha256": sha256(MANIFEST),
        "maps": maps,
        **identity,
    }

    write_manifest(receipt, LOAD_RECEIPT)
    return receipt


def inspect():
    sys.path.insert(0, str(BUILD_DIR))
    import collect

    snapshot = collect.snapshot()
    result = {
        "schema_version": 1,
        "captured_at": timestamp(),
        "loaded": snapshot["loaded"],
        "attachment_mode": snapshot["mode"],
        "program_id": None,
        "program_tag": None,
        "build_manifest": None,
        "object_matches_current_build": None,
        "source_matches_build": None,
        "loaded_object_identity_verified": False,
    }

    if MANIFEST.is_file() and not MANIFEST.is_symlink():
        manifest = json.loads(MANIFEST.read_text())
        result["build_manifest"] = manifest
        if SOURCE.is_file() and not SOURCE.is_symlink():
            result["source_matches_build"] = (
                isinstance(manifest.get("source_sha256"), str)
                and sha256(SOURCE) == manifest.get("source_sha256")
            )
        if OBJECT.is_file() and not OBJECT.is_symlink():
            result["object_matches_current_build"] = (
                sha256(OBJECT) == manifest.get("object_sha256")
            )

    if snapshot["loaded"] == 1:
        program = pinned_program()
        result["program_id"] = program["program_id"]
        result["program_tag"] = program["program_tag"]
        result["program_map_ids"] = program["program_map_ids"]
        current_maps = pinned_maps()
        try:
            validate_program_maps(program, current_maps)
            maps_match_program = True
        except ValueError:
            maps_match_program = False

        if LOAD_RECEIPT.is_file() and not LOAD_RECEIPT.is_symlink():
            receipt = json.loads(LOAD_RECEIPT.read_text(encoding="utf-8"))
            result["load_receipt"] = receipt

            result["loaded_object_identity_verified"] = (
                receipt.get("schema_version") == LOAD_RECEIPT_SCHEMA
                and receipt.get("program_id") == result["program_id"]
                and receipt.get("program_tag") == result["program_tag"]
                and receipt.get("program_map_ids") == result["program_map_ids"]
                and receipt.get("attachment_mode") == result["attachment_mode"]
                and receipt.get("maps") == current_maps
                and maps_match_program
                and receipt.get("object_sha256")
                    == (result["build_manifest"] or {}).get("object_sha256")
                and receipt.get("build_manifest_sha256")
                    == (sha256(MANIFEST) if MANIFEST.is_file() else None)
                and result["source_matches_build"] is True
                and result["object_matches_current_build"] is True
            )

    return result


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)

    b = sub.add_parser("build")
    b.add_argument("--threshold", type=int, required=True)
    b.add_argument("--window-ns", type=int, required=True)
    b.add_argument("--max-sources", type=int, required=True)

    sub.add_parser("inspect")
    sub.add_parser("validate-build")
    sub.add_parser("record-load")
    args = parser.parse_args()

    try:
        if args.action == "build":
            if not (
                1 <= args.threshold <= 9999999
                and 1 <= args.window_ns <= 10**15
                and 1 <= args.max_sources <= 65536
            ):
                raise ValueError("invalid build parameters")
            build(args)
        elif args.action == "validate-build":
            print(json.dumps(verified_build(), indent=2))
        elif args.action == "record-load":
            print(json.dumps(record_load(), indent=2))
        else:
            print(json.dumps(inspect(), indent=2))
        return 0
    except (
        OSError, ValueError, KeyError, ImportError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"fingerprint: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
