#!/usr/bin/env python3
"""Offline OPLA lifecycle journal with injected executor.

Does not start VMs, SSH, sudo, or any system commands.
"""

import fcntl
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STEPS = ("preflight", "create", "configure", "health")
LAB_RE = re.compile(r"lab-[A-Za-z0-9]{4,32}\Z")


class Blocked(RuntimeError):
    pass


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def _valid_timestamp(value):
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def private_parent(path):
    path = Path(path).absolute()

    if path.name in ("", ".", "..") or path.is_symlink():
        raise Blocked("journal path is unsafe or symlink")

    parent = path.parent
    for ancestor in (parent, *parent.parents):
        if ancestor.is_symlink():
            raise Blocked("journal path has symlink ancestor")
    st = parent.lstat()

    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != os.getuid()
        or st.st_mode & 0o077
    ):
        raise Blocked(
            "journal parent must be private and user-owned (0700)"
        )

    return path


def read_state(path, lab_id, *, steps=STEPS):
    if path.is_symlink():
        raise Blocked("journal symlink refused")

    if not path.exists():
        return None

    st = path.lstat()

    if (
        not stat.S_ISREG(st.st_mode)
        or st.st_uid != os.getuid()
        or st.st_mode & 0o077
        or st.st_nlink != 1
    ):
        raise Blocked("unsafe journal file")

    try:
        with path.open("r", encoding="utf-8") as source:
            state = json.load(source)
    except (ValueError, OSError, UnicodeError) as exc:
        raise Blocked("unreadable journal") from exc

    if (
        not isinstance(state, dict)
        or type(state.get("version")) is not int
        or state.get("version") != 1
        or state.get("lab_id") != lab_id
    ):
        raise Blocked("journal identity/version mismatch")

    names = steps
    if "plan" in state and state["plan"] != list(names):
        raise Blocked("journal plan mismatch")
    steps = state.get("steps")

    if (
        not isinstance(steps, dict)
        or set(steps) != set(names)
        or any(
            not isinstance(steps[s], dict)
            or steps[s].get("status")
            not in ("PENDING", "RUNNING", "PASS", "FAILED")
            for s in names
        )
    ):
        raise Blocked("invalid journal states")

    incomplete = False
    for name in names:
        record = steps[name]
        commands = record.get("commands", [])
        if not isinstance(commands, list) or any(
            not isinstance(command, dict)
            or not isinstance(command.get("command_id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", command["command_id"]) is None
            or command.get("status") not in ("PREPARED", "COMPLETED", "CANCELLED", "UNKNOWN")
            or type(command.get("reconciliation_required")) is not bool
            or not isinstance(command.get("argv"), list)
            or not command["argv"]
            or any(not isinstance(arg, str) or not arg for arg in command["argv"])
            for command in commands
        ):
            raise Blocked("invalid command checkpoint")
        if len({command["command_id"] for command in commands}) != len(commands):
            raise Blocked("duplicate command checkpoint identity")
        attempts = record.get("attempts")
        status = record["status"]
        if (
            type(attempts) is not int
            or attempts < 0
            or (status == "PENDING" and attempts != 0)
            or (status != "PENDING" and attempts == 0)
        ):
            raise Blocked("invalid journal attempts")
        if status == "PASS":
            evidence = record.get("evidence")
            if (not isinstance(evidence, dict)
                    or not _valid_timestamp(record.get("started_at"))
                    or not _valid_timestamp(record.get("finished_at"))):
                raise Blocked("PASS stage lacks durable evidence")
            try:
                json.dumps(evidence, allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise Blocked("PASS stage evidence is not serializable") from exc
        if incomplete and status != "PENDING":
            raise Blocked("invalid journal stage order")
        incomplete = incomplete or status != "PASS"

    return state


def save_state(path, state):
    if path.is_symlink():
        raise Blocked("journal symlink refused")

    data = (
        json.dumps(
            state,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
    ).encode()

    fd, tmp = tempfile.mkstemp(
        prefix=".opla-journal-",
        dir=path.parent,
    )

    try:
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

        os.replace(tmp, path)

        dirfd = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY,
        )

        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def run_offline(executor, journal_path, lab_id, *, resume=False,
                steps=STEPS, revalidate=None, restore=None, bind_checkpoint=None):
    """Execute test-injected stages with a persistent journal."""

    if not LAB_RE.fullmatch(lab_id):
        raise Blocked("invalid lab ID")
    steps = tuple(steps)
    if not steps or len(set(steps)) != len(steps):
        raise Blocked("invalid step plan")

    path = private_parent(journal_path)
    lock_path = private_parent(str(path) + ".lock")

    if lock_path.is_symlink():
        raise Blocked("lock symlink refused")

    fd = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
        0o600,
    )

    checkpoint_active = False
    try:
        st = os.fstat(fd)

        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or st.st_mode & 0o077
            or st.st_nlink != 1
        ):
            raise Blocked("unsafe lock file")

        try:
            fcntl.flock(
                fd,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as exc:
            raise Blocked("journal is locked") from exc

        state = read_state(path, lab_id, steps=steps)

        if state is not None and not resume:
            raise Blocked(
                "journal exists; explicit resume required"
            )

        if state is None:
            if resume:
                raise Blocked("cannot resume without journal")

            state = {
                "version": 1,
                "lab_id": lab_id,
                "plan": list(steps),
                "updated_at": timestamp(),
                "steps": {
                    name: {
                        "status": "PENDING",
                        "attempts": 0,
                    }
                    for name in steps
                },
            }

            save_state(path, state)

        # Revalidation runs under the same lock as execution. Never replay an
        # ambiguous operation, even if a later probe happens to look healthy.
        for name in steps:
            record = state["steps"][name]
            evidence = record.get("evidence", {})
            reconcile = isinstance(evidence, dict) and evidence.get("reconciliation_required") is True
            reconcile = reconcile or any(
                command["reconciliation_required"] or command["status"] != "COMPLETED"
                for command in record.get("commands", [])
            )
            if record["status"] == "RUNNING" or (
                name == "create" and record["status"] == "FAILED"
            ) or reconcile:
                raise Blocked(f"{name} interrupted or failed: reconcile resources")

        if resume and (revalidate is not None or restore is not None):
            try:
                if restore is not None:
                    restore(json.loads(json.dumps(state)))
                for name in steps:
                    if revalidate is not None and state["steps"][name]["status"] == "PASS":
                        if revalidate(name) is not True:
                            raise Blocked(f"{name}: revalidation failed")
            except Exception as exc:
                state["last_blocked"] = f"{type(exc).__name__}: {str(exc)[:300]}"
                state["updated_at"] = timestamp()
                save_state(path, state)
                raise Blocked(state["last_blocked"]) from exc
        state.pop("last_blocked", None)

        def checkpoint(name, command):
            if not checkpoint_active or state["steps"][name]["status"] != "RUNNING":
                raise Blocked("command checkpoint outside active stage")
            snapshot = json.loads(json.dumps(command, allow_nan=False))
            commands = state["steps"][name].setdefault("commands", [])
            matching = [index for index, old in enumerate(commands)
                        if old["command_id"] == snapshot["command_id"]]
            if matching:
                index = matching[0]
                if commands[index]["argv"] != snapshot["argv"]:
                    raise Blocked("command identity changed")
                commands[index] = snapshot
            else:
                if snapshot.get("status") != "PREPARED":
                    raise Blocked("command was not prepared")
                commands.append(snapshot)
            state["updated_at"] = timestamp()
            save_state(path, state)

        checkpoint_active = True
        if bind_checkpoint is not None:
            bind_checkpoint(checkpoint)

        for name in steps:
            record = state["steps"][name]

            if record["status"] == "PASS":
                continue

            index = steps.index(name)

            if index > 0:
                preceding = steps[index - 1]

                if state["steps"][preceding]["status"] != "PASS":
                    raise Blocked(
                        f"{name}: preceding stage incomplete"
                    )

            record["status"] = "RUNNING"
            record["attempts"] = record.get("attempts", 0) + 1
            record["started_at"] = timestamp()
            state["updated_at"] = timestamp()

            save_state(path, state)

            try:
                result = executor(name)

                if isinstance(result, dict):
                    # Ensure evidence is serializable before claiming success.
                    json.dumps(result, allow_nan=False)
                    record["evidence"] = result
                elif result is True:
                    record["evidence"] = {"result": True}
                else:
                    raise RuntimeError(
                        "executor returned non-True"
                    )

            except Exception as exc:
                record["status"] = "FAILED"
                evidence = getattr(exc, "evidence", None)
                if isinstance(evidence, dict):
                    try:
                        json.dumps(evidence, allow_nan=False)
                    except (ValueError, TypeError):
                        pass
                    else:
                        record["evidence"] = evidence
                record["error"] = (
                    f"{type(exc).__name__}: {str(exc)[:300]}"
                )
                record["finished_at"] = timestamp()
                state["updated_at"] = timestamp()

                save_state(path, state)
                return state

            record["status"] = "PASS"
            record.pop("error", None)
            record["finished_at"] = timestamp()
            state["updated_at"] = timestamp()

            save_state(path, state)

        return state

    finally:
        checkpoint_active = False
        try:
            if bind_checkpoint is not None:
                bind_checkpoint(None)
        finally:
            os.close(fd)
