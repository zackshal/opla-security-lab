#!/usr/bin/env python3
"""Validate immutable OPLA role image inputs before lab creation."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "images"

ROLE_IMAGES = {
    "victim": ("debian-12-xdp.qcow2", (3 * 1024**3, 10 * 1024**3)),
    "attacker": ("debian-12-attacker.qcow2", 4 * 1024**3),
    "client": ("debian-12-client.qcow2", 4 * 1024**3),
}


def verify(role, filename, expected_size, *, images=None, runner=None):
    images = IMAGES if images is None else Path(images)
    runner = subprocess.run if runner is None else runner
    image = images / filename
    checksum = images / (filename + ".sha256")
    role_file = images / (filename + ".role")

    for path in (image, checksum, role_file):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or unsafe file: {path}")

    if role_file.read_text().strip() != role:
        raise ValueError(f"role mismatch: {filename}")

    parts = checksum.read_text().strip().split()
    if len(parts) != 2 or parts[1].lstrip("*") != filename:
        raise ValueError(f"invalid checksum metadata: {filename}")

    expected_hash = parts[0].lower()
    if len(expected_hash) != 64 or any(
        c not in "0123456789abcdef" for c in expected_hash
    ):
        raise ValueError(f"invalid SHA-256: {filename}")

    digest = hashlib.sha256()
    with image.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)

    if digest.hexdigest() != expected_hash:
        raise ValueError(f"checksum mismatch: {filename}")

    result = runner(
        ["qemu-img", "info", "--output=json", str(image)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    info = json.loads(result.stdout)

    if info.get("format") != "qcow2":
        raise ValueError(f"invalid format: {filename}")

    allowed_sizes = (
        expected_size
        if isinstance(expected_size, tuple)
        else (expected_size,)
    )
    if info.get("virtual-size") not in allowed_sizes:
        raise ValueError(f"unexpected virtual size: {filename}")

    if info.get("backing-filename"):
        raise ValueError(f"unexpected backing image: {filename}")

    print(f"PASS: {role} | {filename} | SHA-256 verified")
    return {"role": role, "filename": filename, "sha256": expected_hash,
            "virtual_size": info["virtual-size"]}


def main():
    try:
        for role, (filename, size) in ROLE_IMAGES.items():
            verify(role, filename, size)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: image verification failed: {exc}", file=sys.stderr)
        return 2

    print("PASS: all OPLA role images verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
