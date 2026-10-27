#!/usr/bin/env python3
"""Build/verify a reviewable OPLA code bundle; NEVER installs or executes it.

SHA-256 detects accidental changes, not publisher authenticity. A trusted
administrator must approve the bundle before a separate privileged installer.
"""
import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath

# Only source/config required by the application. Runtime state and disk images
# must never be shipped in a privileged code bundle.
ROOT_ITEMS = ("Makefile", "bootstrap.sh", "bin", "cloud-init", "xdp",
              "security", "deploy", "scenarios", "ansible", "monitoring")
SUFFIXES = {".py", ".sh", ".bash", ".c", ".h", ".yaml", ".yml",
            ".json", ".cfg", ".conf", ".ini", ".rules", ".service",
            ".mk", ".txt"}
NAMES = {"Makefile", "Dockerfile", "bootstrap.sh", "ansible.cfg"}
DENIED_DIRS = {".git", "__pycache__", ".venv", "venv", "runtime",
               "images", "logs", "build", "dist", "artifacts", "node_modules"}
DENIED_NAMES = {"state.env", ".env", "known_hosts", "authorized_keys",
                "id_rsa", "id_ed25519", "credentials.json", "secrets.yml",
                "secrets.yaml", "mail.json"}
DENIED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".qcow2", ".img",
                   ".sqlite", ".db", ".log", ".pcap", ".gz", ".tar"}
MAX_FILE = 1024 * 1024
MAX_FILES = 1500
MAX_TOTAL = 20 * 1024 * 1024


def collect(root):
    root = Path(root).absolute()
    result = {}
    for item in ROOT_ITEMS:
        base = root / item
        if not base.exists():
            continue
        candidates = [base] if base.is_file() else base.rglob("*")
        for path in candidates:
            relative = path.relative_to(root)
            if any(part in DENIED_DIRS for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"symlink forbidden: {relative}")
            if not path.is_file():
                continue
            if path.name in DENIED_NAMES or path.suffix.lower() in DENIED_SUFFIXES:
                continue
            if path.name not in NAMES and path.suffix.lower() not in SUFFIXES:
                continue
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_FILE:
                raise ValueError(f"unsafe source file: {relative}")
            if st.st_mode & 0o6000:
                raise ValueError(f"setuid/setgid source forbidden: {relative}")
            result[relative.as_posix()] = path.read_bytes()
    if not result or len(result) > MAX_FILES or sum(map(len, result.values())) > MAX_TOTAL:
        raise ValueError("bundle source count/size outside limits")
    for critical in ("bin/opla-create-launcher.py", "bin/opla-lab-configure-launcher.py",
                     "bin/create-lab.sh", "bin/opla-lifecycle-lock.py", "Makefile"):
        if critical not in result:
            raise ValueError(f"missing critical source: {critical}")
    return dict(sorted(result.items()))


def metadata(files):
    return {"format": "opla-code-bundle-v1", "files": {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        for name, data in files.items()
    }}


def safe_member(name):
    path = PurePosixPath(name)
    return (not path.is_absolute() and len(path.parts) > 1
            and path.parts[0] == "source" and ".." not in path.parts
            and all(p not in ("", ".") for p in path.parts))


def add_bytes(tar, name, contents):
    info = tarfile.TarInfo(name)
    info.size = len(contents)
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    tar.addfile(info, io.BytesIO(contents))


def build(source, output):
    files = collect(source)
    manifest = (json.dumps(metadata(files), sort_keys=True,
                           separators=(",", ":")) + "\n").encode()
    output = Path(output)
    if output.is_symlink() or output.exists():
        raise ValueError("output already exists; refusing overwrite")
    with output.open("xb") as handle:
        with tarfile.open(fileobj=handle, mode="w:gz") as tar:
            add_bytes(tar, "MANIFEST.json", manifest)
            for name, contents in files.items():
                add_bytes(tar, "source/" + name, contents)
    return len(files)


def verify(bundle):
    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_file():
        raise ValueError("bundle missing or symlink")
    files = {}
    manifest = None
    total = 0
    with tarfile.open(bundle, "r:gz") as tar:
        for member in tar:
            if not member.isfile() or member.pax_headers or member.size > MAX_FILE:
                raise ValueError("unsafe tar member")
            name = member.name
            if name != "MANIFEST.json" and not safe_member(name):
                raise ValueError(f"unsafe member path: {name}")
            if name in files or (name == "MANIFEST.json" and manifest is not None):
                raise ValueError(f"duplicate member: {name}")
            total += member.size
            if total > MAX_TOTAL or len(files) > MAX_FILES:
                raise ValueError("bundle exceeds limits")
            contents = tar.extractfile(member).read()
            if name == "MANIFEST.json":
                manifest = json.loads(contents)
            else:
                files[name[len("source/"):]] = contents
    if manifest is None or manifest != metadata(dict(sorted(files.items()))):
        raise ValueError("manifest/hash mismatch")
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    b = sub.add_parser("build")
    b.add_argument("--source", required=True)
    b.add_argument("--output", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--bundle", required=True)
    args = parser.parse_args()
    try:
        count = build(args.source, args.output) if args.action == "build" else verify(args.bundle)
    except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as error:
        parser.exit(2, f"BLOCKED: {error}\n")
    print(f"PASS: {args.action}: {count} source files")


if __name__ == "__main__":
    main()
