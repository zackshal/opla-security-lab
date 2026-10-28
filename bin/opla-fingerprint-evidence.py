#!/usr/bin/env python3
"""Validate XDP program identity across an archived experiment."""

import json
from pathlib import Path

IDENTITY = (
    "program_id",
    "program_tag",
    "attachment_mode",
)

def verify(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("fingerprints must be JSON objects")

    if before.get("loaded") != 1 or after.get("loaded") != 1:
        return {"status": "invalid", "reason": "XDP not loaded throughout experiment"}

    for key in IDENTITY:
        a, b = before.get(key), after.get(key)
        if a is None or b is None:
            return {"status": "unverified", "reason": f"missing {key}"}
        if a != b:
            return {"status": "invalid", "reason": f"{key} changed"}

    for name, item in (("before", before), ("after", after)):
        if item.get("loaded_object_identity_verified") is not True:
            return {
                "status": "unverified",
                "reason": f"{name} load receipt not verified",
            }

    a = before.get("load_receipt")
    b = after.get("load_receipt")

    if not isinstance(a, dict) or not isinstance(b, dict):
        return {"status": "unverified", "reason": "load receipt missing"}

    for key in ("object_sha256", "build_manifest_sha256"):
        if not isinstance(a.get(key), str) or not a[key]:
            return {"status": "unverified", "reason": f"missing {key}"}
        if a[key] != b.get(key):
            return {"status": "invalid", "reason": f"{key} changed"}

    return {
        "status": "verified",
        "program_id": before["program_id"],
        "program_tag": before["program_tag"],
        "attachment_mode": before["attachment_mode"],
        "object_sha256": a["object_sha256"],
    }


def verify_directory(directory):
    directory = Path(directory)
    paths = [
        directory / "fingerprint-before.json",
        directory / "fingerprint-after.json",
    ]

    if any(p.is_symlink() for p in paths):
        return {"status": "invalid", "reason": "unsafe fingerprint symlink"}

    if not all(p.is_file() for p in paths):
        return {"status": "unverified", "reason": "fingerprints unavailable"}

    try:
        before, after = (
            json.loads(p.read_text(encoding="utf-8")) for p in paths
        )
        return verify(before, after)
    except (OSError, ValueError, TypeError) as exc:
        return {"status": "invalid", "reason": str(exc)}
