#!/usr/bin/env python3
"""Verify completeness and integrity of a live-acceptance run.

Modes:
  --fill-hashes DIR     attach SHA-256 of every file under evidence/ and reports/
  --check DIR           validate manifest, verify hashes, emit PASS/BLOCKED
"""
import argparse, hashlib, json, pathlib, sys, datetime

def sha256(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def iter_files(base: pathlib.Path):
    for p in sorted(base.rglob("*")):
        if p.is_file():
            yield p.relative_to(base).as_posix(), p

def fill_hashes(root: pathlib.Path):
    m = json.loads((root / "manifest.json").read_text())
    arts = []
    for sub in ("evidence", "reports", "logs"):
        base = root / sub
        if not base.is_dir():
            continue
        for rel, p in iter_files(base):
            arts.append({"path": f"{sub}/{rel}", "size": p.stat().st_size,
                         "sha256": sha256(p)})
    m["artifacts"] = arts
    (root / "manifest.json").write_text(json.dumps(m, indent=2))

REQUIRED_STEPS = {
    "bootstrap", "images", "lab_create", "lab_ready",
    "xdp_stats_before", "xdp_stats_after",
    "ids_status_before", "ids_status_after",
    "scenario_check", "scenario_run",
}

def check(root: pathlib.Path) -> int:
    blockers = []
    try:
        m = json.loads((root / "manifest.json").read_text())
    except Exception as e:
        print(json.dumps({"overall_status": "BLOCKED", "blockers": [f"manifest: {e}"]}))
        return 2

    steps = {s["name"]: s for s in m.get("steps", [])}
    for r in sorted(REQUIRED_STEPS):
        if r not in steps:
            blockers.append(f"missing step: {r}")
        elif steps[r]["status"] != "PASS":
            blockers.append(f"step failed: {r}")

    if not m.get("lab", {}).get("id"):
        blockers.append("missing lab.id")
    if m.get("git_dirty"):
        blockers.append("git tree was dirty during run")

    # Hash re-verification
    for a in m.get("artifacts", []):
        p = root / a["path"]
        if not p.is_file():
            blockers.append(f"missing artifact: {a['path']}")
        elif sha256(p) != a["sha256"]:
            blockers.append(f"tampered artifact: {a['path']}")

    # Client continuity evidence
    client_hits = list((root / "evidence").rglob("client-probes*.json"))
    if not client_hits:
        blockers.append("missing client continuity evidence (client-probes*.json)")
    else:
        total = 0
        try:
            for h in client_hits:
                j = json.loads(h.read_text())
                total += len(j.get("samples", j if isinstance(j, list) else []))
        except Exception as e:
            blockers.append(f"unreadable client evidence: {e}")
        if total < 2:
            blockers.append("client continuity has <2 samples")

    # Zabbix
    if "OPLA_ZABBIX_USER" not in __import__("os").environ:
        m["zabbix"] = "SKIPPED"

    m["overall_status"] = "PASS" if not blockers else "BLOCKED"
    m["blockers"] = blockers
    m["verified_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    (root / "manifest.json").write_text(json.dumps(m, indent=2))
    (root / "verification.json").write_text(json.dumps(
        {"overall_status": m["overall_status"], "blockers": blockers}, indent=2))
    print(json.dumps({"overall_status": m["overall_status"], "blockers": blockers}, indent=2))
    return 0 if not blockers else 2

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--fill-hashes", metavar="DIR")
    g.add_argument("--check", metavar="DIR")
    a = ap.parse_args()
    if a.fill_hashes:
        fill_hashes(pathlib.Path(a.fill_hashes)); sys.exit(0)
    else:
        sys.exit(check(pathlib.Path(a.check)))
