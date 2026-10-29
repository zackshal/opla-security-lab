#!/usr/bin/env python3
"""Validate immutable OPLA role image inputs before lab creation."""

import hashlib
import json
import re
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

ROLE_PACKAGES = {
    "victim": {"clang", "llvm", "libbpf-dev", "linux-libc-dev", "bpftool",
               "iproute2", "python3", "python3-yaml", "nginx", "hping3",
               "curl", "tcpdump", "cloud-init", "openssh-server", "gcc",
               "make", "suricata", "suricata-update", "nftables", "logrotate"},
    "attacker": {"hping3", "nmap", "arp-scan", "yersinia", "tcpdump",
                 "curl", "python3", "iproute2", "cloud-init", "openssh-server"},
    "client": {"curl", "python3", "iproute2", "cloud-init", "openssh-server"},
}

ROLE_STEMS = {
    "victim": "debian-12-xdp",
    "attacker": "debian-12-attacker",
    "client": "debian-12-client",
}


def role_candidates(role, images=None):
    images = IMAGES if images is None else Path(images)
    stem = ROLE_STEMS[role]
    candidates = []
    base = images / f"{stem}.qcow2"
    if base.exists():
        candidates.append((1, base.name))
    pattern = re.compile(re.escape(stem) + r"-g([2-9][0-9]*)\.qcow2\Z")
    for path in images.glob(f"{stem}-g*.qcow2"):
        match = pattern.fullmatch(path.name)
        if match:
            candidates.append((int(match.group(1)), path.name))
    usable = []
    for generation, filename in candidates:
        metadata = images / (filename + ".packages")
        if metadata.is_symlink() or not metadata.is_file():
            continue
        try:
            packages = set(metadata.read_text(encoding="utf-8").split())
        except (OSError, UnicodeError):
            continue
        if packages == ROLE_PACKAGES[role]:
            usable.append((generation, filename))
    return sorted(usable, reverse=True)


def select_role_image(role, *, images=None, runner=None):
    images = IMAGES if images is None else Path(images)
    candidates = role_candidates(role, images)
    if not candidates:
        raise ValueError(
            f"no current {role} image; prepare an immutable new generation with "
            f"make image ROLE={role}. Existing images are preserved."
        )
    filename = candidates[0][1]
    size = ROLE_IMAGES[role][1]
    verify(role, filename, size, images=images, runner=runner, quiet=True)
    return images / filename


def verify(role, filename, expected_size, *, images=None, runner=None, quiet=False):
    images = IMAGES if images is None else Path(images)
    runner = subprocess.run if runner is None else runner
    image = images / filename
    checksum = images / (filename + ".sha256")
    role_file = images / (filename + ".role")
    packages_file = images / (filename + ".packages")

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

    if packages_file.is_symlink() or not packages_file.is_file():
        raise ValueError(
            f"missing dependency inventory for {role} image; it predates "
            "the current module set. Preserve it and prepare a fresh role image."
        )
    try:
        declared_packages = set(packages_file.read_text(encoding="utf-8").split())
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"invalid dependency inventory: {filename}") from exc
    if declared_packages != ROLE_PACKAGES[role]:
        missing = sorted(ROLE_PACKAGES[role] - declared_packages)
        extra = sorted(declared_packages - ROLE_PACKAGES[role])
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise ValueError(f"stale dependency inventory for {role}: {'; '.join(details)}")

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

    # The sidecar makes the role contract visible to the host, while this
    # read-only guest-file check binds that claim to the actual qcow2 content.
    guest_manifest = runner(
        ["virt-cat", "-a", str(image), "/etc/opla-dependencies-verified"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    manifest_text = guest_manifest.stdout
    # Older generated role images escaped the dpkg format separators twice,
    # leaving literal backslash-t/backslash-n sequences in one line. Accept
    # that already-published format while new images use real delimiters.
    if "\\n" in manifest_text and len(manifest_text.splitlines()) == 1:
        records = manifest_text.split("\\n")
        separator = "\\t"
    else:
        records = manifest_text.splitlines()
        separator = "\t"
    guest_packages = {
        line.split(separator, 1)[0].split(":", 1)[0]
        for line in records
        if line.strip()
    }
    if guest_packages != declared_packages:
        raise ValueError(f"guest dependency manifest differs from sidecar: {filename}")

    if not quiet:
        print(f"PASS: {role} | {filename} | SHA-256 verified")
    return {"role": role, "filename": filename, "sha256": expected_hash,
            "virtual_size": info["virtual-size"]}


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--select", choices=tuple(ROLE_IMAGES),
                        help="verify and print the current immutable image for one role")
    args = parser.parse_args()
    try:
        if args.select:
            print(select_role_image(args.select))
            return 0
        for role, (filename, size) in ROLE_IMAGES.items():
            image = select_role_image(role)
            print(f"PASS: current {role} image: {image}")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: image verification failed: {exc}", file=sys.stderr)
        return 2

    print("PASS: all OPLA role images verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
