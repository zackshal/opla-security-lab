#!/usr/bin/env python3
"""Native-Codex project support: local task ledger, evidence and hook guardrails.

No agent scheduler, arbitrary command runner, deployment or permission mutation.
"""

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import stat
import signal
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("harness_private_io", ROOT / "bin/opla-lab-progress.py")
private_io = importlib.util.module_from_spec(spec)
spec.loader.exec_module(private_io)
CHECKS = {
    "harness": [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_agent_harness.py", "-v"],
    "compile": [sys.executable, "-m", "compileall", "-q", "bin", "tests"],
    "portable": ["make", "check"],
    "acceptance": ["make", "acceptance-offline"],
}
PROTECTED = ("AGENTS.md", ".codex", ".agents", "harness", "bin/opla-harness.py",
             "bin/opla-lab-progress.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def baseline(root=ROOT):
    """Fingerprint tracked and nonignored source, including dirty/untracked files.

    Ignored runtime artifacts, secrets and .git internals are never enumerated.
    """
    root = Path(root)
    files = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
    hashes = {}
    for raw in sorted(set(files) - {b""}):
        name = os.fsdecode(raw)
        path = root / name
        if path.is_symlink():
            hashes[name] = "symlink:" + digest(os.readlink(path).encode())
        elif path.is_file():
            hashes[name] = digest(path.read_bytes()) + ":" + str(path.stat().st_mode & 0o777)
        elif not path.exists():
            hashes[name] = "deleted"
    return {"head": git(root, "rev-parse", "HEAD").decode().strip(),
            "tree_sha256": digest(json.dumps(hashes, sort_keys=True).encode()), "files": hashes}


def scope_path(value):
    path = Path(value)
    if path.is_absolute() or not value or any(part in ("..", ".git") for part in path.parts) or str(path) == ".":
        raise ValueError("invalid task scope")
    return path.as_posix()


def overlaps(left, right):
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


@contextmanager
def ledger(path):
    path = private_io.private_parent(path)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_mode & 0o077:
            raise ValueError("unsafe task ledger lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if path.exists():
            st = path.lstat()
            if not path.is_file() or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_mode & 0o077:
                raise ValueError("unsafe task ledger")
            state = json.loads(path.read_text())
            if state.get("version") != 1 or not isinstance(state.get("tasks"), dict):
                raise ValueError("invalid task ledger")
        else:
            state = {"version": 1, "tasks": {}}
        yield state
        private_io.save_state(path, state)
    finally:
        os.close(fd)


def claim(state, task_id, actor, paths, *, root=ROOT, dependencies=(), required_checks=("compile",)):
    if not re.fullmatch(r"[a-z0-9-]{1,64}", task_id) or not actor:
        raise ValueError("invalid task or actor")
    if task_id in state["tasks"]:
        raise ValueError("task already exists; inspect before resuming")
    paths = [scope_path(path) for path in paths]
    if not paths:
        raise ValueError("explicit task scope required")
    if not required_checks or any(check not in CHECKS for check in required_checks):
        raise ValueError("explicit known required checks needed")
    for task in state["tasks"].values():
        if task["status"] != "complete" and any(overlaps(a, b) for a in paths for b in task["paths"]):
            raise ValueError("conflicting active file claim")
    if any(state["tasks"].get(dep, {}).get("status") != "complete" for dep in dependencies):
        raise ValueError("dependencies incomplete")
    state["tasks"][task_id] = {
        "actor": actor, "paths": paths, "dependencies": list(dependencies),
        "status": "running", "baseline": baseline(root), "started_at": time.time(),
        "checks": [], "review": None, "rework": 0,
        "policy_events": [],
        "required_checks": list(required_checks),
        "usage": {"tokens": None, "cost": None, "source": "native usage not imported"},
    }


def record_policy(task, actor, violation, note):
    """Persist an observed policy event without claiming hook/runtime proof.

    Hook denials are not automatically connected to this private ledger: the
    operator or integrator must explicitly record the observed event and its
    evidence note.  This keeps synthetic policy tests separate from trusted
    native hook telemetry.
    """
    if (not actor or not isinstance(violation, str) or not violation.strip()
            or not isinstance(note, str) or not note.strip()
            or task["status"] not in ("running", "submitted")):
        raise ValueError("explicit policy event actor, violation and evidence note required")
    task.setdefault("policy_events", []).append({
        "actor": actor, "violation": violation.strip()[:200],
        "note": note.strip()[:1000], "at": time.time(),
    })
    # Policy evidence changes the reviewed evidence set; require a fresh
    # independent review before completion.
    task["review"] = None


def supervised_check(argv, *, cwd, capture_output, timeout, check):
    """Only used for fixed offline checks; own process group, bounded cleanup."""
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            process.communicate(timeout=2)
        except BaseException:
            pass
        # The leader can exit while descendants remain; terminate the owned group.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.communicate(timeout=2)
        except BaseException:
            # The original timeout/interruption remains the authoritative
            # result; inability to prove a final reap keeps the check
            # unresolved rather than turning it into a pass.
            pass
        raise
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def record_check(task, check, directory, *, root=ROOT, runner=None, checkpoint=lambda: None):
    if check not in CHECKS or task["status"] not in ("running", "submitted"):
        raise ValueError("invalid check or task state")
    before = baseline(root)
    if any(receipt["check"] == check for receipt in task["checks"]):
        task["rework"] += 1
    started = time.time()
    task["status"] = "checking"
    argv = CHECKS[check]
    receipt = {"check": check, "argv": argv, "cwd": str(root), "status": "running",
               "started_at": started, "tree_sha256": before["tree_sha256"]}
    task["checks"].append(receipt)
    task["review"] = None
    checkpoint()
    try:
        result = (supervised_check if runner is None else runner)(
            argv, cwd=root, capture_output=True, timeout=300, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        receipt.update(status="blocked", error_type=type(exc).__name__, finished_at=time.time())
        task["status"] = "blocked"
        checkpoint()
        return receipt
    output = (result.stdout or b"") + (result.stderr or b"")
    log = Path(directory) / (digest(output) + ".log")
    try:
        fd = os.open(log, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        st = log.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1
                or st.st_mode & 0o077 or digest(log.read_bytes()) != digest(output)):
            raise ValueError("unsafe check log")
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
    count = re.search(rb"Ran (\d+) tests?", output)
    receipt.update({"check": check, "argv": argv, "cwd": str(root), "status": "executed",
               "started_at": started, "finished_at": time.time(), "returncode": result.returncode,
               "log": log.name, "log_sha256": digest(output), "tree_sha256": before["tree_sha256"],
               "tests": int(count[1]) if count else None,
               "stable_tree": before["tree_sha256"] == baseline(root)["tree_sha256"]})
    receipt["duration_seconds"] = receipt["finished_at"] - started
    task["review"] = None
    task["status"] = "submitted"
    checkpoint()
    return receipt


def reconcile(task, reviewer, note, *, root=ROOT):
    if (not reviewer or reviewer == task["actor"] or not note
            or task["status"] not in ("checking", "blocked")):
        raise ValueError("independent reconciliation note and interrupted/blocked task required")
    for receipt in task["checks"]:
        if receipt["status"] in ("running", "blocked") and "reconciliation" not in receipt:
            receipt["reconciliation"] = {"reviewer": reviewer, "note": note, "at": time.time(),
                                         "tree_sha256": baseline(root)["tree_sha256"]}
    task["status"] = "running"
    task["review"] = None


def review(task, reviewer, *, root=ROOT, note=""):
    if not reviewer or reviewer == task["actor"] or task["status"] != "submitted":
        raise ValueError("independent reviewer and submitted task required")
    task["review"] = {"reviewer": reviewer, "tree_sha256": baseline(root)["tree_sha256"],
                      "reviewed_at": time.time(), "note": note}


def complete(task, directory, *, root=ROOT):
    actual = baseline(root)
    current = actual["tree_sha256"]
    if task["status"] != "submitted" or not task["review"] or task["review"]["tree_sha256"] != current:
        raise ValueError("missing or stale independent review")
    if not task["checks"]:
        raise ValueError("no executed test evidence")
    previous = task["baseline"]["files"]
    changed = [path for path in set(previous) | set(actual["files"])
               if previous.get(path) != actual["files"].get(path)]
    if any(not any(path == owned or path.startswith(owned + "/") for owned in task["paths"])
           for path in changed):
        raise ValueError("changes outside assigned scope; integrator review required")
    latest = {}
    for check in task["checks"]:
        if check.get("status") != "executed" and "reconciliation" not in check:
            raise ValueError("unresolved interrupted or blocked check")
        latest[check["check"]] = check
    if not set(task["required_checks"]).issubset(latest):
        raise ValueError("required acceptance checks missing")
    for check in latest.values():
        if check.get("status") != "executed":
            raise ValueError("reconciled check still needs a successful retry")
        log = Path(directory) / check["log"]
        if (Path(check["log"]).name != check["log"] or log.is_symlink()
                or not log.is_file() or digest(log.read_bytes()) != check["log_sha256"]
                or check["status"] != "executed" or check["returncode"] != 0
                or not check["stable_tree"] or check["tree_sha256"] != current):
            raise ValueError("failed, missing, modified or stale test evidence")
    task["status"] = "complete"
    task["finished_at"] = time.time()


def shell_reason(command):
    """Conservative direct-command subset, not a shell interpreter or sandbox."""
    if not isinstance(command, str) or any(char in command for char in "\n\r;&|`$<>()"):
        return "compound, substituted or malformed shell requires human review"
    try:
        argv = shlex.split(command)
    except ValueError:
        return "unparseable shell"
    if not argv:
        return "empty command"
    executable = Path(argv[0]).name
    if argv[0] != executable:
        return "absolute/relative executable wrappers require review"
    if executable == "git":
        if len(argv) < 2 or argv[1] not in ("status", "log", "diff", "rev-parse", "show", "ls-files"):
            return "Git mutation or unknown command blocked"
        if any(arg.startswith(("--output", "--ext-diff", "--textconv")) for arg in argv[2:]):
            return "Git external helper/output blocked"
        return None
    if executable in ("rg", "cat", "head", "tail", "wc", "pwd"):
        if executable == "rg" and any(arg.startswith("--pre") for arg in argv[1:]):
            return "rg executable preprocessor blocked"
        return None
    if executable == "make" and argv[1:] in (["check"], ["acceptance-offline"], ["harness-check"]):
        return None
    if executable in ("python3", "python"):
        if argv[1:] in (["-m", "compileall", "-q", "bin", "tests"],
                        ["-m", "unittest", "discover", "-s", "tests", "-p", "test_agent_harness.py", "-v"]):
            return None
        if len(argv) > 2 and argv[1] == "bin/opla-harness.py" and argv[2] in ("claim", "check", "review", "complete", "status", "metrics", "evaluate", "suggest", "reconcile", "policy"):
            return None
    return "unreviewed executable, wrapper, script or infrastructure operation blocked"


def hook(event):
    name = event.get("hook_event_name")
    if name in ("SessionStart", "PreCompact"):
        return {"hookSpecificOutput": {"hookEventName": name, "additionalContext":
                "Read root AGENTS.md and PLANS.md. Codex is the orchestrator. One shared-tree writer. "
                "Inspect task ledger after interruption; never treat agent claims as executed tests. "
                "No VM/network/privileged operations. See docs/agent-harness.md."}}
    if name != "PreToolUse":
        return {}
    tool = event.get("tool_name")
    data = event.get("tool_input", {})
    reason = None
    if not isinstance(data, dict):
        reason = "malformed tool input"
    elif tool in ("Bash", "exec_command"):
        reason = shell_reason(data.get("command", data.get("cmd")))
    elif tool in ("apply_patch", "Edit", "Write"):
        patch = data.get("command", "")
        files = re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", patch, re.M)
        if not files:
            reason = "unrecognized edit payload"
        for match in files:
            path = next(value for value in match if value)
            if Path(path).is_absolute():
                try:
                    path = Path(path).relative_to(ROOT).as_posix()
                except ValueError:
                    reason = "edit outside project"
                    continue
            try:
                path = scope_path(path)
            except ValueError:
                reason = "unsafe edit path"
                continue
            effective = ROOT / path
            if any(part.is_symlink() for part in (effective, *effective.parents)):
                reason = "edit through symlink requires human review"
                continue
            if any(overlaps(path, protected) for protected in PROTECTED):
                reason = "safety/harness changes need explicit human review before activation"
    elif tool not in ("spawn_agent", "Agent", "send_message", "wait_agent", "update_plan"):
        reason = "unreviewed tool requires human review"
    if reason:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}
    return {}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("hook", "claim", "check", "review", "complete", "status", "metrics", "evaluate", "suggest", "reconcile", "policy"))
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--task")
    parser.add_argument("--actor")
    parser.add_argument("--note", default="")
    parser.add_argument("--violation", default="")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--depends", action="append", default=[])
    parser.add_argument("--check", choices=CHECKS)
    parser.add_argument("--require-check", choices=CHECKS, action="append", default=[])
    args = parser.parse_args(argv)
    if args.action == "evaluate":
        cases = json.loads((ROOT / "harness/fixtures/policy-cases.json").read_text())
        failed = [index for index, case in enumerate(cases)
                  if (shell_reason(case["command"]) is not None) != case["deny"]]
        print(json.dumps({"status": "FAILED" if failed else "PASS", "cases": len(cases),
                          "failed": failed, "policy_modified": False}))
        return int(bool(failed))
    if args.action == "hook":
        try:
            event = json.load(sys.stdin)
            if not isinstance(event, dict):
                raise ValueError("hook event must be an object")
            print(json.dumps(hook(event)))
            return 0
        except (ValueError, TypeError):
            print("Malformed OPLA hook input denied", file=sys.stderr)
            return 2
    if args.ledger is None:
        parser.error("explicit private --ledger required")
    try:
        exit_code = 0
        with ledger(args.ledger) as state:
            if args.action == "claim":
                claim(state, args.task, args.actor, args.path, dependencies=args.depends,
                      required_checks=args.require_check or ["compile"])
            elif args.action in ("status", "metrics", "suggest"):
                if args.action == "status":
                    print(json.dumps(state, indent=2))
                else:
                    checks = [c for task in state["tasks"].values() for c in task["checks"]]
                    failures = {}
                    for check in checks:
                        if check.get("returncode") != 0:
                            key = check["check"] + ":" + check.get("error_type", check["status"])
                            failures[key] = failures.get(key, 0) + 1
                    if args.action == "suggest":
                        print(json.dumps({"proposals": [key for key, count in failures.items() if count >= 2],
                                          "review_required": True, "policy_modified": False}))
                        return 0
                    tasks = list(state["tasks"].values())
                    successful_tasks = sum(task.get("status") == "complete" for task in tasks)
                    terminal_tasks = sum(task.get("status") in ("complete", "blocked") for task in tasks)
                    now = time.time()
                    task_seconds = sum((task.get("finished_at", now) - task["started_at"])
                                       for task in tasks if task.get("started_at"))
                    policy_events = [event for task in tasks for event in task.get("policy_events", [])]
                    print(json.dumps({"tasks": len(tasks), "successful_tasks": successful_tasks,
                                      "terminal_tasks": terminal_tasks,
                                      "success_rate": (successful_tasks / terminal_tasks if terminal_tasks else None),
                                      "executed_checks": sum(c["status"] == "executed" for c in checks),
                                      "successful_checks": sum(c.get("returncode") == 0 for c in checks),
                                      "repeated_failures": failures,
                                      "rework": sum(task.get("rework", 0) for task in tasks),
                                      "task_seconds": task_seconds,
                                      "check_seconds": sum(c.get("finished_at", now) - c["started_at"] for c in checks),
                                      "resource_usage": {"tokens": None, "cost": None,
                                                         "cpu_seconds": None, "max_rss_kb": None,
                                                         "source": "native usage not imported"},
                                      "policy_violations": len(policy_events),
                                      "policy_event_types": sorted({event["violation"] for event in policy_events})}))
            elif args.action == "policy":
                record_policy(state["tasks"][args.task], args.actor, args.violation, args.note)
            else:
                task = state["tasks"][args.task]
                if args.action == "check":
                    receipt = record_check(task, args.check, args.ledger.parent,
                                           checkpoint=lambda: private_io.save_state(args.ledger, state))
                    print(json.dumps(receipt))
                    exit_code = (2 if receipt["status"] != "executed"
                                 else 0 if receipt["returncode"] == 0 else 1)
                elif args.action == "review":
                    review(task, args.actor, note=args.note)
                elif args.action == "reconcile":
                    reconcile(task, args.actor, args.note)
                else:
                    complete(task, args.ledger.parent)
        return exit_code
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, private_io.Blocked) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
