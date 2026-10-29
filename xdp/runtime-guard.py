#!/usr/bin/env python3
"""Fail-closed parsing of iproute2/bpftool observations for XDP lifecycle."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

PIN_ROOT = Path("/sys/fs/bpf/opla")
PROGRAM_PIN = PIN_ROOT / "program"
RECEIPT = Path("/tmp/xdp-build/load-receipt.json")
SUPPORTED_MODES = {"drv", "native", "skb", "generic", "hw", "offload"}
EXPECTED_MAP_PINS = {"syn_windows", "xdp_stats", "xdp_policy"}
LOAD_RECEIPT_SCHEMA = 2
MAX_RECEIPT_BYTES = 64 * 1024


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_json_constant(value):
    raise ValueError(f"invalid load receipt JSON constant: {value}")


def read_receipt():
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    try:
        fd = os.open(RECEIPT, flags)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != 0 or info.st_mode & 0o022
                or info.st_size > MAX_RECEIPT_BYTES):
            raise ValueError("load receipt has unsafe file identity")
        chunks, remaining = [], MAX_RECEIPT_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_RECEIPT_BYTES:
            raise ValueError("load receipt exceeds size limit")
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys,
                            parse_constant=reject_json_constant)
        if not isinstance(result, dict):
            raise ValueError("load receipt is malformed")
        return result
    finally:
        if fd is not None:
            os.close(fd)


def parse_link(payload, interface="ens3"):
    if isinstance(payload, str):
        payload = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise ValueError("link observation must contain exactly one interface")
    link = payload[0]
    if link.get("ifname") != interface:
        raise ValueError("link observation has unexpected interface identity")
    # iproute2 omits the `xdp` object entirely when the interface has no
    # attached XDP program.  Do not confuse that normal representation with
    # malformed data: the exact interface identity and single-record shape
    # have already been checked above.  An explicitly present but malformed
    # object remains fail-closed.
    if "xdp" not in link:
        return {"mode": "off", "program_id": None}
    xdp = link["xdp"]
    if not isinstance(xdp, dict):
        raise ValueError("XDP attachment state is malformed")
    attached = xdp.get("attached")
    if attached == "off":
        if xdp.get("prog_id") not in (None, 0):
            raise ValueError("link reports off with a program ID")
        prog = xdp.get("prog")
        if isinstance(prog, dict) and prog.get("id") not in (None, 0):
            raise ValueError("link reports off with a program ID")
        return {"mode": "off", "program_id": None}
    if attached not in SUPPORTED_MODES:
        raise ValueError("XDP attachment mode is unknown")
    identifiers = []
    prog_id = xdp.get("prog_id")
    if prog_id is not None:
        identifiers.append(prog_id)
    prog = xdp.get("prog")
    if prog is not None:
        if not isinstance(prog, dict) or "id" not in prog:
            raise ValueError("XDP program identity is malformed")
        identifiers.append(prog["id"])
    if (not identifiers or any(type(value) is not int or value <= 0 for value in identifiers)
            or len(set(identifiers)) != 1):
        raise ValueError("XDP program identity is missing or inconsistent")
    return {"mode": attached, "program_id": identifiers[0]}


def parse_pinned_program(payload):
    if isinstance(payload, str):
        payload = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    if isinstance(payload, list):
        if len(payload) != 1:
            raise ValueError("pinned program query must return exactly one program")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise ValueError("pinned program identity is malformed")
    program_id, tag, map_ids = payload.get("id"), payload.get("tag"), payload.get("map_ids")
    if (type(program_id) is not int or program_id <= 0
            or not isinstance(tag, str) or not tag
            or not isinstance(map_ids, list) or not map_ids
            or any(type(map_id) is not int or map_id <= 0 for map_id in map_ids)
            or len(set(map_ids)) != len(map_ids)):
        raise ValueError("pinned program identity is incomplete")
    return {"program_id": program_id, "program_tag": tag,
            "program_map_ids": sorted(map_ids)}


def classify_unload(link, pinned_program=None, receipt=None):
    """Return a cleanup state only when attachment and OPLA receipt agree."""
    if isinstance(link, str) or isinstance(link, list):
        link = parse_link(link)
    if not isinstance(link, dict) or link.get("mode") not in {"off", *SUPPORTED_MODES}:
        raise ValueError("link state is malformed")
    if pinned_program is None:
        if link["mode"] == "off":
            return "already-unloaded"
        raise ValueError("an attached XDP program has no OPLA pin identity")
    pinned = parse_pinned_program(pinned_program)
    if not isinstance(receipt, dict):
        raise ValueError("load receipt is missing or malformed; preserve pins")
    receipt_schema = receipt.get("schema_version")
    if (receipt_schema not in {1, LOAD_RECEIPT_SCHEMA}
            or type(receipt.get("program_id")) is not int
            or receipt.get("program_id") != pinned["program_id"]
            or receipt.get("program_tag") != pinned["program_tag"]):
        raise ValueError("load receipt does not identify the pinned program")
    receipt_maps = receipt.get("maps")
    receipt_map_ids = receipt.get("program_map_ids")
    if receipt_schema == LOAD_RECEIPT_SCHEMA:
        if (not isinstance(receipt_map_ids, list)
                or any(type(item) is not int or item <= 0 for item in receipt_map_ids)
                or len(set(receipt_map_ids)) != len(receipt_map_ids)
                or receipt_map_ids != pinned["program_map_ids"]
                or not isinstance(receipt_maps, dict)
                or set(receipt_maps) != EXPECTED_MAP_PINS
                or any(not isinstance(entry, dict) or type(entry.get("id")) is not int
                       or entry["id"] <= 0 or not isinstance(entry.get("type"), str)
                       for entry in receipt_maps.values())
                or {entry.get("id") for entry in receipt_maps.values()
                    if isinstance(entry, dict)} != set(pinned["program_map_ids"])):
            raise ValueError("load receipt maps do not match pinned program map IDs")
    elif receipt_map_ids is not None:
        if (not isinstance(receipt_map_ids, list)
                or any(type(item) is not int or item <= 0 for item in receipt_map_ids)
                or len(set(receipt_map_ids)) != len(receipt_map_ids)
                or receipt_map_ids != pinned["program_map_ids"]):
            raise ValueError("legacy load receipt map IDs differ from pinned program")
    if receipt_schema == 1 and receipt_maps is not None:
        if (not isinstance(receipt_maps, dict)
                or set(receipt_maps) != EXPECTED_MAP_PINS
                or any(not isinstance(entry, dict) or type(entry.get("id")) is not int
                       or entry["id"] <= 0 or not isinstance(entry.get("type"), str)
                       for entry in receipt_maps.values())
                or {entry["id"] for entry in receipt_maps.values()}
                    != set(pinned["program_map_ids"])):
            raise ValueError("legacy receipt map identity is malformed or differs from program")
    if link["mode"] == "off":
        return "pinned-unattached"
    if link.get("program_id") != pinned["program_id"]:
        raise ValueError("interface attachment is foreign or has changed; preserve pins")
    if receipt.get("attachment_mode") not in {link["mode"], "native" if link["mode"] == "drv" else link["mode"],
                                                "generic" if link["mode"] == "skb" else link["mode"],
                                                "offload" if link["mode"] == "hw" else link["mode"]}:
        raise ValueError("load receipt attachment mode differs from current link")
    return "attached-owned"


def validate_map_pin_names(names):
    if set(names) != EXPECTED_MAP_PINS:
        raise ValueError("map pin inventory differs from expected OPLA maps; preserve resources")


def validate_map_pin_identity(receipt_maps, observed_maps, program_map_ids):
    if receipt_maps is not None and (
            not isinstance(receipt_maps, dict) or set(receipt_maps) != EXPECTED_MAP_PINS):
        raise ValueError("load receipt has incomplete map identities; preserve resources")
    if not isinstance(observed_maps, dict) or set(observed_maps) != EXPECTED_MAP_PINS:
        raise ValueError("observed map identities are incomplete; preserve resources")
    for name in EXPECTED_MAP_PINS:
        actual = observed_maps[name]
        if (not isinstance(actual, dict)
                or type(actual.get("id")) is not int or actual["id"] <= 0
                or not isinstance(actual.get("type"), str)):
            raise ValueError(f"pinned map identity is invalid: {name}")
        if receipt_maps is not None:
            expected = receipt_maps[name]
            if (not isinstance(expected, dict) or type(expected.get("id")) is not int
                    or expected["id"] <= 0 or expected.get("id") != actual.get("id")
                    or not isinstance(expected.get("type"), str)
                    or expected.get("type") != actual.get("type")):
                raise ValueError(f"pinned map identity differs from load receipt: {name}")
    if ({entry["id"] for entry in observed_maps.values()}
            != set(program_map_ids)):
        raise ValueError("load receipt maps do not match pinned program map IDs")


def command(argv):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=5, check=True)
    return result.stdout


def inspect_link(interface="ens3"):
    return parse_link(command(["ip", "-j", "link", "show", "dev", interface]), interface)


def inspect_unload():
    link = inspect_link()
    if not PROGRAM_PIN.exists():
        if PIN_ROOT.exists() or PIN_ROOT.is_symlink():
            raise ValueError("partial OPLA pin tree has no program pin; preserve resources")
        return classify_unload(link)
    if PROGRAM_PIN.is_symlink():
        raise ValueError("program pin is a symlink; preserve resources")
    try:
        root_info = PIN_ROOT.lstat()
        maps_root = PIN_ROOT / "maps"
        maps_info = maps_root.lstat()
    except OSError as exc:
        raise ValueError("cannot inspect OPLA pin directories") from exc
    if not stat.S_ISDIR(root_info.st_mode) or not stat.S_ISDIR(maps_info.st_mode):
        raise ValueError("OPLA pin root or maps path is not a real directory")
    program = parse_pinned_program(command(["bpftool", "-j", "prog", "show", "pinned", str(PROGRAM_PIN)]))
    try:
        receipt = read_receipt()
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"load receipt unavailable: {exc}") from None
    state = classify_unload(link, program, receipt)
    if state != "already-unloaded":
        try:
            entries = list(maps_root.iterdir())
        except OSError as exc:
            raise ValueError("cannot inspect OPLA map pins") from exc
        validate_map_pin_names({entry.name for entry in entries})
        if any(entry.is_symlink() for entry in entries):
            raise ValueError("map pin path is a symlink; preserve resources")
        observed_maps = {}
        for entry in entries:
            metadata = command(["bpftool", "-j", "map", "show", "pinned", str(entry)])
            parsed = json.loads(metadata, object_pairs_hook=reject_duplicate_keys)
            if isinstance(parsed, list):
                if len(parsed) != 1:
                    raise ValueError("pinned map query returned multiple records")
                parsed = parsed[0]
            if not isinstance(parsed, dict):
                raise ValueError("pinned map metadata is malformed")
            observed_maps[entry.name] = {"id": parsed.get("id"), "type": parsed.get("type")}
        validate_map_pin_identity(receipt.get("maps"), observed_maps,
                                  program["program_map_ids"])
    return state


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args == ["load-check"]:
            link = inspect_link()
            if link["mode"] != "off":
                raise ValueError("ens3 already has an XDP attachment; no replacement attempted")
            print("off")
        elif args == ["unload-check"]:
            print(inspect_unload())
        else:
            raise ValueError("expected load-check or unload-check")
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
