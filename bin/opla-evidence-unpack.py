#!/usr/bin/env python3
"""Convert bounded OPLA evidence export into a local JSONL artifact."""

import argparse
import json
import os
import sys
from pathlib import Path

NAMES = {
    "suricata": "eve.json",
    "scan": "events.jsonl",
}
MAX_INPUT_BYTES = 4 * 1024 * 1024


def unpack(export_file, directory, kind):
    if kind not in NAMES:
        raise ValueError("unsupported source")

    export_file = Path(export_file)
    directory = Path(directory)

    if export_file.is_symlink() or not export_file.is_file():
        raise ValueError("unsafe or missing export file")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("unsafe or missing output directory")
    if export_file.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("oversized evidence export")

    data = json.loads(export_file.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("source") != kind:
        raise ValueError("incorrect export source")

    status = data.get("status")
    if status not in ("captured", "unavailable"):
        raise ValueError("unsupported export status")

    records = data.get("records")
    if not isinstance(records, list) or not all(
        isinstance(record, dict) for record in records
    ):
        raise ValueError("invalid exported records")

    if status == "unavailable" and records:
        raise ValueError("unavailable source contains records")

    metadata = {key: value for key, value in data.items() if key != "records"}
    metadata["exported_records"] = len(records)

    meta_path = directory / (kind + "-evidence-meta.json")
    log_path = directory / NAMES[kind]

    if meta_path.is_symlink() or log_path.is_symlink():
        raise ValueError("output symlinks rejected")

    if status == "captured":
        with log_path.open("x", encoding="utf-8") as stream:
            os.chmod(log_path, 0o600)
            for record in records:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    with meta_path.open("x", encoding="utf-8") as stream:
        os.chmod(meta_path, 0o600)
        json.dump(metadata, stream, ensure_ascii=False, indent=2)
        stream.write("\n")

    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=tuple(NAMES), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = unpack(args.input, args.output_dir, args.kind)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
