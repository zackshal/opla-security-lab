#!/usr/bin/env python3
"""Prepare an UNPRIVILEGED review tree from a pinned OPLA bundle.

Not an installer: does not chown, sudo, execute code or modify /opt/opla.
The expected SHA-256 must be obtained independently from a trusted reviewer.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("opla_bundle_stage", HERE / "opla-release-bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
HASH = re.compile(r"[a-fA-F0-9]{64}\Z")


def _fsync_directory(path):
    """Durably flush a directory without following symlinked directories."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def safe_directory(path):
    """Require an existing tree without symlink ancestors."""
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError(f"unsafe staging directory: {parent}")
    return path


def stage(archive, destination, expected_sha256):
    if os.geteuid() == 0:
        raise ValueError("root execution forbidden: offline user staging only")
    if not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256):
        raise ValueError("expected SHA-256 must be 64 hexadecimal digits")
    archive = Path(archive).absolute()
    st = archive.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError("bundle must be a regular, non-hardlinked file")
    if st.st_size > 30 * 1024 * 1024:
        raise ValueError("bundle too large")
    with archive.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    if digest != expected_sha256.lower():
        raise ValueError("bundle differs from independently approved SHA-256")
    count = bundle.verify(archive)
    destination = Path(destination).absolute()
    parent = safe_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination already exists")
    # This is not a root installer: the destination stays user-owned.
    if parent.stat().st_uid != os.getuid():
        raise ValueError("destination parent must belong to invoking user")
    if parent.stat().st_mode & 0o022:
        raise ValueError("destination parent writable by group/others")
    temp = Path(tempfile.mkdtemp(prefix=".opla-stage-", dir=parent))
    os.chmod(temp, 0o700)
    try:
        seen = set()
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if member.name == "MANIFEST.json":
                    continue
                if (not member.isfile() or member.pax_headers
                        or not bundle.safe_member(member.name)):
                    raise ValueError("unsafe archive entry")
                relative = member.name.removeprefix("source/")
                if (relative in seen or not relative or
                        any(part.startswith(".") for part in Path(relative).parts)):
                    raise ValueError("duplicate or hidden source path")
                seen.add(relative)
                target = temp / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                data = tar.extractfile(member).read()
                with target.open("xb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(target, 0o600)
        if len(seen) != count:
            raise ValueError("unexpected file count")
        attestation = {
            "format": "opla-user-review-stage-v1",
            "bundle_sha256": digest,
            "file_count": count,
            "warning": "NOT TRUSTED, NOT INSTALLED, DO NOT EXECUTE AS ROOT",
        }
        review = temp / "REVIEW.json"
        with review.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(attestation, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(review, 0o600)
        _fsync_directory(temp)
        os.replace(temp, destination)
        _fsync_directory(parent)
    except BaseException:
        if temp.exists():
            shutil.rmtree(temp)
        raise
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    try:
        count = stage(args.bundle, args.destination, args.expected_sha256)
    except (ValueError, OSError, tarfile.TarError) as exc:
        parser.exit(2, f"BLOCKED: {exc}\n")
    print(f"PASS: staged {count} files for unprivileged review only")


if __name__ == "__main__":
    main()
