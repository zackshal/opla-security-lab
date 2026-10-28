#!/usr/bin/env python3
"""Read-only comparison of archived OPLA SYN experiments."""

import argparse
import csv
import importlib.util
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_experiment_report_compare",
    ROOT / "bin/opla-experiment-report.py",
)
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


fp_spec = importlib.util.spec_from_file_location(
    "opla_fp_evidence_compare",
    ROOT / "bin/opla-fingerprint-evidence.py",
)
fp_evidence = importlib.util.module_from_spec(fp_spec)
fp_spec.loader.exec_module(fp_evidence)

FIELDS = (
    "experiment", "lab_id", "source_sha256", "xdp_mode",
    "generator_exit_code", "syn", "passed", "dropped",
    "drop_percent", "status", "fingerprint_status", "error",
)


def context_metadata(folder):
    path = folder / "context.txt"
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or unsafe context.txt")

    content = path.read_text(encoding="utf-8")
    lab = re.search(r"^LAB_DIR=/var/lib/opla/(lab-[A-Za-z0-9]+)$", content, re.M)
    sha = re.search(
        r"^([0-9a-f]{64})  xdp/xdp_ddos_protect\.c$",
        content,
        re.M,
    )
    return {
        "lab_id": lab.group(1) if lab else None,
        "source_sha256": sha.group(1) if sha else None,
    }


def compare(folder):
    row = {name: None for name in FIELDS}
    row["experiment"] = folder.name
    fp_result = fp_evidence.verify_directory(folder)
    row["fingerprint_status"] = fp_result["status"]

    try:
        row.update(context_metadata(folder))

        before_path = folder / "before.json"
        after_path = folder / "after.json"
        if before_path.is_symlink() or after_path.is_symlink():
            raise ValueError("unsafe XDP snapshot")

        before = json.loads(before_path.read_text(encoding="utf-8"))
        after = json.loads(after_path.read_text(encoding="utf-8"))

        modes = (before.get("mode"), after.get("mode"))
        if modes[0] != modes[1]:
            raise ValueError("XDP attachment mode changed")

        row["xdp_mode"] = modes[0]

        result = reporter.build_report(folder)
        delta = result["xdp"]["deltas"]

        row["generator_exit_code"] = result["generator_exit_code"]
        row["syn"] = delta["syn"]
        row["passed"] = delta["pass"]
        row["dropped"] = delta["drop"]

        total = delta["pass"] + delta["drop"]
        row["drop_percent"] = (
            round(100 * delta["drop"] / total, 2)
            if total > 0 else None
        )

        if row["fingerprint_status"] == "invalid":
            row["status"] = "invalid_fingerprint"
            row["error"] = fp_result["reason"]
        elif delta["syn"] != total:
            row["status"] = "counter_mismatch"
        elif row["generator_exit_code"] != 0:
            row["status"] = "generator_failed"
        else:
            row["status"] = "valid"

    except (OSError, ValueError, KeyError, TypeError) as exc:
        row["status"] = "invalid"
        row["error"] = str(exc)

    return row


def collect(root):
    root = Path(root)
    return [
        compare(folder)
        for folder in sorted(root.glob("scenario-syn-*"))
        if folder.is_dir() and not folder.is_symlink()
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, default=ROOT / "reports")
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    args = parser.parse_args()

    if not args.reports.is_dir() or args.reports.is_symlink():
        parser.error("reports directory unavailable or unsafe")

    rows = collect(args.reports)

    if args.format == "json":
        print(json.dumps({
            "schema_version": 1,
            "mode": "offline_comparison",
            "experiments": rows,
            "valid": sum(row["status"] == "valid" for row in rows),
            "invalid": sum(row["status"] != "valid" for row in rows),
            "interpretation": (
                "Source hashes are not proof of identical loaded BPF programs. "
                "DROP percentages are observational, not detection accuracy."
            ),
        }, indent=2, ensure_ascii=False))
    else:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        print(output.getvalue(), end="")

    return 0


if __name__ == "__main__":
    sys.exit(main())
