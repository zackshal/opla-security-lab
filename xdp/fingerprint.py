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
    if MANIFEST.is_symlink() or OBJECT.is_symlink():
        raise ValueError("unsafe build artifacts")
    if not MANIFEST.is_file() or not OBJECT.is_file():
        raise ValueError("build manifest or BPF object missing")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("invalid build manifest")

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
    if type(program_id) is not int or not isinstance(tag, str) or not tag:
        raise ValueError("incomplete BPF program identity")

    return {"program_id": program_id, "program_tag": tag}


def record_load():
    manifest = verified_build()

    sys.path.insert(0, str(BUILD_DIR))
    import collect

    snapshot = collect.snapshot()
    if snapshot["loaded"] != 1:
        raise ValueError("BPF program is not attached")

    identity = pinned_program()
    receipt = {
        "schema_version": 1,
        "loaded_at": timestamp(),
        "attachment_mode": snapshot["mode"],
        "object_sha256": manifest["object_sha256"],
        "build_manifest_sha256": sha256(MANIFEST),
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
        "loaded_object_identity_verified": False,
    }

    if MANIFEST.is_file() and not MANIFEST.is_symlink():
        manifest = json.loads(MANIFEST.read_text())
        result["build_manifest"] = manifest
        if OBJECT.is_file() and not OBJECT.is_symlink():
            result["object_matches_current_build"] = (
                sha256(OBJECT) == manifest.get("object_sha256")
            )

    if snapshot["loaded"] == 1:
        program = run_json(
            "bpftool", "-j", "prog", "show", "pinned",
            "/sys/fs/bpf/opla/program",
        )
        if isinstance(program, list):
            if len(program) != 1:
                raise ValueError("unexpected pinned program count")
            program = program[0]

        result["program_id"] = program["id"]
        result["program_tag"] = program.get("tag")

        if LOAD_RECEIPT.is_file() and not LOAD_RECEIPT.is_symlink():
            receipt = json.loads(LOAD_RECEIPT.read_text(encoding="utf-8"))
            result["load_receipt"] = receipt

            result["loaded_object_identity_verified"] = (
                receipt.get("schema_version") == 1
                and receipt.get("program_id") == result["program_id"]
                and receipt.get("program_tag") == result["program_tag"]
                and receipt.get("attachment_mode") == result["attachment_mode"]
                and receipt.get("object_sha256")
                    == (result["build_manifest"] or {}).get("object_sha256")
                and receipt.get("build_manifest_sha256")
                    == (sha256(MANIFEST) if MANIFEST.is_file() else None)
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
