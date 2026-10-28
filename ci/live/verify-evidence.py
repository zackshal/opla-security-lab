#!/usr/bin/env python3
"""Verify completeness and integrity of a live-acceptance run.

Modes:
  --fill-hashes DIR     attach SHA-256 of every file under evidence/ and reports/
  --check DIR           validate manifest, verify hashes, emit PASS/BLOCKED
"""
import argparse, hashlib, json, pathlib, re, stat, sys, datetime

REQUIRED_EVIDENCE = (
    "evidence/preflight.json",
    "evidence/evidence-status.json",
    "evidence/bpftool-prog-before.json",
    "evidence/bpftool-map-before.json",
    "evidence/nft-ruleset-before.txt",
    "evidence/ip-addr-before.txt",
    "evidence/ip-route-before.txt",
    "evidence/ip-link-before.txt",
    "evidence/bpftool-prog-after.json",
    "evidence/bpftool-map-after.json",
    "evidence/nft-ruleset-after.txt",
    "evidence/ip-addr-after.txt",
    "evidence/ip-route-after.txt",
    "evidence/ip-link-after.txt",
    "evidence/vm-victim-dpkg.txt",
    "evidence/vm-attacker-dpkg.txt",
    "evidence/vm-client-dpkg.txt",
)
REQUIRED_PREFLIGHT_FIELDS = {
    "platform", "arch", "kernel", "os_id", "os_version", "kvm",
    "ram_available_mb", "disk_available_gib", "sudo_nopasswd", "outbound_debian",
    "docker_compose",
}
REQUIRED_PREFLIGHT_TOOLS = (
    "qemu-system-x86_64", "qemu-img", "virt-customize", "virt-resize",
    "cloud-localds", "dnsmasq", "ip", "nft", "flock", "systemd-run",
    "systemctl", "python3", "make", "git", "jq", "clang", "bpftool",
    "curl", "ssh", "scp", "docker",
)
REQUIRED_JSON_EVIDENCE = (
    "evidence/bpftool-prog-before.json",
    "evidence/bpftool-map-before.json",
    "evidence/bpftool-prog-after.json",
    "evidence/bpftool-map-after.json",
)

def safe_path(root: pathlib.Path, relative: str):
    """Return an output-local regular path, rejecting traversal and links."""
    if not isinstance(relative, str) or not relative or pathlib.Path(relative).is_absolute():
        return None
    base = root.resolve()
    candidate = base / relative
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(base)
    except (OSError, RuntimeError, ValueError):
        return None
    cursor = candidate
    while cursor != base:
        if cursor.is_symlink():
            return None
        cursor = cursor.parent
    return resolved

def sha256(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def regular_file(p: pathlib.Path) -> bool:
    """Accept only a regular, single-link file owned by this output tree."""
    try:
        info = p.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1

def safe_root(root: pathlib.Path) -> bool:
    """The acceptance output root itself must be a real directory."""
    try:
        info = root.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)

def iter_files(base: pathlib.Path):
    for p in sorted(base.rglob("*")):
        if p.is_symlink():
            raise ValueError(f"symlink artifact: {p}")
        if p.exists():
            if not regular_file(p):
                raise ValueError(f"non-regular or hardlink artifact: {p}")
            yield p.relative_to(base).as_posix(), p

def fill_hashes(root: pathlib.Path):
    if not safe_root(root):
        raise ValueError("unsafe output root")
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
    "bootstrap", "images", "lab_create", "lab_ready", "lab_activate",
    "xdp_stats_before", "xdp_stats_after",
    "ids_status_before", "ids_status_after",
    "scenario_check", "scenario_run",
}

def check(root: pathlib.Path) -> int:
    blockers = []
    if not safe_root(root):
        print(json.dumps({"overall_status": "BLOCKED",
                          "blockers": ["unsafe output root"]}))
        return 2
    try:
        m = json.loads((root / "manifest.json").read_text())
    except Exception as e:
        print(json.dumps({"overall_status": "BLOCKED", "blockers": [f"manifest: {e}"]}))
        return 2
    if not isinstance(m, dict):
        print(json.dumps({"overall_status": "BLOCKED",
                          "blockers": ["manifest must be a JSON object"]}))
        return 2

    raw_steps = m.get("steps", [])
    steps = {}
    if not isinstance(raw_steps, list):
        blockers.append("steps is not a list")
    else:
        for index, step in enumerate(raw_steps):
            if (not isinstance(step, dict)
                    or not isinstance(step.get("name"), str)
                    or step.get("status") not in {"PASS", "FAIL"}
                    or type(step.get("duration_s")) is not int
                    or type(step.get("exit_code")) is not int):
                blockers.append(f"malformed step record: {index}")
                continue
            if step["name"] in steps:
                blockers.append(f"duplicate step record: {step['name']}")
                continue
            steps[step["name"]] = step
    if type(m.get("schema_version")) is not int or m["schema_version"] != 1:
        blockers.append("schema_version is not 1")
    if m.get("platform") not in {"gitlab", "github", "local"}:
        blockers.append("platform is invalid")
    if (not isinstance(m.get("commit"), str)
            or re.fullmatch(r"[0-9a-f]{40}", m["commit"]) is None):
        blockers.append("commit is not a 40-character lowercase SHA-1")
    for r in sorted(REQUIRED_STEPS):
        if r not in steps:
            blockers.append(f"missing step: {r}")
        elif steps[r]["status"] != "PASS":
            blockers.append(f"step failed: {r}")

    lab = m.get("lab", {})
    if not isinstance(lab, dict):
        blockers.append("lab is not an object")
    elif (not isinstance(lab.get("id"), str)
          or re.fullmatch(r"lab-[A-Za-z0-9]{8}", lab["id"]) is None):
        blockers.append("lab.id is invalid")
    elif not isinstance(lab.get("scenario"), str) or not lab["scenario"]:
        blockers.append("lab.scenario is invalid")
    if not isinstance(m.get("git_dirty"), bool):
        blockers.append("git_dirty is not a boolean")
    elif m["git_dirty"]:
        blockers.append("git tree was dirty during run")
    evidence = m.get("evidence", {})
    if not isinstance(evidence, dict) or evidence.get("status") != "PASS":
        blockers.append("mandatory evidence is incomplete")
    preflight = m.get("preflight", {})
    if not isinstance(preflight, dict):
        blockers.append("preflight is not an object")
    elif preflight.get("status") == "SKIPPED":
        blockers.append(preflight.get("reason", "preflight was skipped"))

    preflight_path = safe_path(root, "evidence/preflight.json")
    if preflight_path is None or not regular_file(preflight_path):
        blockers.append("preflight.json is missing or unsafe")
    else:
        try:
            preflight_data = json.loads(preflight_path.read_text())
            if not isinstance(preflight_data, dict):
                blockers.append("preflight.json is not an object")
            else:
                missing_fields = sorted(REQUIRED_PREFLIGHT_FIELDS - preflight_data.keys())
                if missing_fields:
                    blockers.append("preflight.json missing fields: " + ",".join(missing_fields))
                else:
                    if preflight_data.get("platform") != "Linux":
                        blockers.append("preflight platform is not Linux")
                    for key in ("kvm", "sudo_nopasswd", "outbound_debian"):
                        if preflight_data.get(key) != "ok":
                            blockers.append(f"preflight gate failed: {key}")
                    if preflight_data.get("docker_compose") != "ok":
                        blockers.append("preflight gate failed: docker_compose")
                    for tool in REQUIRED_PREFLIGHT_TOOLS:
                        if preflight_data.get("tool_" + tool) != "ok":
                            blockers.append(f"preflight tool unavailable: {tool}")
                    for key, minimum in (("ram_available_mb", 5120),
                                         ("disk_available_gib", 30)):
                        try:
                            if int(preflight_data[key]) < minimum:
                                blockers.append(f"preflight threshold failed: {key}")
                        except (TypeError, ValueError):
                            blockers.append(f"preflight value is not numeric: {key}")
        except Exception as e:
            blockers.append(f"unreadable preflight.json: {e}")

    status_path = safe_path(root, "evidence/evidence-status.json")
    if status_path is None or not regular_file(status_path):
        blockers.append("evidence-status.json is missing or unsafe")
    else:
        try:
            evidence_status = json.loads(status_path.read_text())
            if (not isinstance(evidence_status, dict)
                    or evidence_status.get("status") != "PASS"
                    or evidence_status.get("missing") != []):
                blockers.append("evidence-status.json status is not PASS")
        except Exception as e:
            blockers.append(f"unreadable evidence-status.json: {e}")

    for relative in REQUIRED_EVIDENCE:
        p = safe_path(root, relative)
        if p is None or not regular_file(p):
            blockers.append(f"missing or unsafe evidence: {relative}")
        elif p.stat().st_size == 0:
            blockers.append(f"empty evidence: {relative}")

    for relative in REQUIRED_JSON_EVIDENCE:
        p = safe_path(root, relative)
        if p is not None and regular_file(p):
            try:
                json.loads(p.read_text())
            except Exception as e:
                blockers.append(f"unreadable JSON evidence {relative}: {e}")

    # Hash re-verification
    artifacts = m.get("artifacts", [])
    if not isinstance(artifacts, list):
        blockers.append("artifacts is not a list")
        artifacts = []
    artifact_paths = set()
    for index, a in enumerate(artifacts):
        if not isinstance(a, dict) or not isinstance(a.get("path"), str) or not isinstance(a.get("sha256"), str):
            blockers.append(f"malformed artifact record: {index}")
            continue
        if a["path"] in artifact_paths:
            blockers.append(f"duplicate artifact: {a['path']}")
        artifact_paths.add(a["path"])
        p = safe_path(root, a["path"])
        if p is None or not regular_file(p):
            blockers.append(f"missing or unsafe artifact: {a['path']}")
        elif not isinstance(a.get("size"), int) or a["size"] != p.stat().st_size:
            blockers.append(f"artifact size mismatch: {a['path']}")
        elif sha256(p) != a["sha256"]:
            blockers.append(f"tampered artifact: {a['path']}")
    for relative in REQUIRED_EVIDENCE:
        if relative not in artifact_paths:
            blockers.append(f"missing artifact hash: {relative}")

    # Client continuity evidence
    client_hits = list((root / "evidence").rglob("client-probes*.json"))
    if not client_hits:
        blockers.append("missing client continuity evidence (client-probes*.json)")
    else:
        total = 0
        try:
            for h in client_hits:
                relative = h.relative_to(root).as_posix()
                if safe_path(root, relative) is None or not regular_file(h):
                    blockers.append(f"unsafe client evidence: {relative}")
                    continue
                j = json.loads(h.read_text())
                samples = j if isinstance(j, list) else j.get("samples") if isinstance(j, dict) else None
                if not isinstance(samples, list):
                    blockers.append(f"client evidence samples is not a list: {relative}")
                    continue
                total += len(samples)
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
