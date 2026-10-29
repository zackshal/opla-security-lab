#!/usr/bin/env python3
"""Hold OPLA lifecycle locks while configuring a lab as the invoking user."""

import importlib.util
import json
import math
import os
import pwd
import re
import signal
import subprocess
import stat
import sys
import tempfile
from datetime import datetime, timezone
from contextlib import ExitStack
from pathlib import Path

ROOT = Path("/var/lib/opla")
HERE = Path(__file__).resolve().parent
VALID_LAB = re.compile(r"lab-[A-Za-z0-9]{4,32}\Z")
DEFAULT_CONFIGURE_TIMEOUT = 900
MAX_CONFIGURE_TIMEOUT = 3600
CONFIGURE_TERMINATION_GRACE = 5
RECONCILIATION_FILENAME = "configure-reconciliation.json"
MAX_RECONCILIATION_BYTES = 64 * 1024



def verify_trusted_code():
    """Refuse privileged execution from a user-writable source tree."""
    project = HERE.parent

    for directory in (project, *project.parents, HERE):
        st = directory.lstat()
        if (
            not stat.S_ISDIR(st.st_mode)
            or st.st_uid != 0
            or st.st_mode & 0o022
        ):
            raise RuntimeError(
                f"untrusted source directory: {directory}"
            )

    for name in (
        "opla-lab-configure-launcher.py",
        "opla-lifecycle-lock.py",
        "opla-lab-configure.sh",
        "opla-create-launcher.py",
        "create-lab.sh",
        "opla-registry.py",
    ):
        path = HERE / name
        st = path.lstat()
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != 0
            or st.st_mode & 0o022
            or st.st_nlink != 1
        ):
            raise RuntimeError(
                f"untrusted privileged source: {path}"
            )

def load_locks():
    spec = importlib.util.spec_from_file_location(
        "opla_configure_locks",
        HERE / "opla-lifecycle-lock.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_arguments(argv):
    if len(argv) != 2:
        raise ValueError("expected LAB_ID and matching confirmation")

    lab_id, confirmation = argv

    if not VALID_LAB.fullmatch(lab_id):
        raise ValueError("invalid laboratory ID")

    if confirmation != lab_id:
        raise ValueError("laboratory confirmation mismatch")

    return lab_id


def invoking_user():
    if os.geteuid() != 0:
        raise RuntimeError("root launcher required")

    try:
        uid = int(os.environ["SUDO_UID"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("invoke through sudo from a regular user") from exc

    if uid <= 0:
        raise RuntimeError("regular invoking user required")

    return pwd.getpwuid(uid)


def validate_configure_timeout(timeout):
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0
            or timeout > MAX_CONFIGURE_TIMEOUT):
        raise ValueError(
            f"configure timeout must be finite, positive and <= {MAX_CONFIGURE_TIMEOUT}s"
        )
    return timeout


def configure_timeout_from_env(env=None):
    raw = (os.environ if env is None else env).get(
        "OPLA_CONFIGURE_TIMEOUT", str(DEFAULT_CONFIGURE_TIMEOUT)
    )
    try:
        timeout = int(raw, 10)
    except (TypeError, ValueError) as exc:
        raise ValueError("OPLA_CONFIGURE_TIMEOUT must be an integer number of seconds") from exc
    return validate_configure_timeout(timeout)


def run_configure(command, *, cwd, env, preexec_fn, timeout=DEFAULT_CONFIGURE_TIMEOUT, pass_fds=(),
                  popen_factory=None, killpg=os.killpg, grace=CONFIGURE_TERMINATION_GRACE):
    """Run configure in an isolated process group and reap it on timeout.

    A timeout only proves that this child group was signalled and reaped. It
    does not reconcile the retained lab's VMs, network, registry or services.
    """
    timeout = validate_configure_timeout(timeout)
    if (isinstance(grace, bool) or not isinstance(grace, (int, float))
            or not math.isfinite(grace) or grace <= 0):
        raise ValueError("configure termination grace must be finite and positive")
    dispatch = subprocess.Popen if popen_factory is None else popen_factory
    process = dispatch(
        command,
        cwd=cwd,
        env=env,
        preexec_fn=preexec_fn,
        start_new_session=True,
        pass_fds=pass_fds,
    )
    try:
        return subprocess.CompletedProcess(command, process.wait(timeout=timeout))
    except (subprocess.TimeoutExpired, OSError) as exc:
        cleanup = {"status": "unknown", "term_sent": False, "kill_sent": False}
        try:
            killpg(process.pid, signal.SIGTERM)
            cleanup["term_sent"] = True
        except ProcessLookupError:
            cleanup["status"] = "already-exited"
        except OSError as cleanup_error:
            cleanup["error_type"] = type(cleanup_error).__name__
        try:
            process.wait(timeout=grace)
            cleanup["status"] = "reaped-after-term"
        except subprocess.TimeoutExpired:
            try:
                killpg(process.pid, signal.SIGKILL)
                cleanup["kill_sent"] = True
            except ProcessLookupError:
                cleanup["status"] = "already-exited"
            except OSError as cleanup_error:
                cleanup["error_type"] = type(cleanup_error).__name__
            try:
                process.wait()
                cleanup["status"] = "reaped-after-kill"
            except OSError as reap_error:
                cleanup["error_type"] = type(reap_error).__name__
        except OSError as wait_error:
            cleanup["error_type"] = type(wait_error).__name__
            try:
                killpg(process.pid, signal.SIGKILL)
                cleanup["kill_sent"] = True
            except ProcessLookupError:
                cleanup["status"] = "already-exited"
            except OSError as kill_error:
                cleanup["kill_error_type"] = type(kill_error).__name__
            try:
                process.wait()
                cleanup["status"] = "reaped-after-error"
            except OSError as reap_error:
                cleanup["reap_error_type"] = type(reap_error).__name__
        exc.cleanup_evidence = cleanup
        raise


def _receipt_stat(path, *, require_root_owner):
    try:
        state = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(state.st_mode) or state.st_nlink != 1
            or state.st_mode & 0o077
            or (require_root_owner and state.st_uid != 0)):
        raise RuntimeError("unsafe configure reconciliation receipt")
    if state.st_size > MAX_RECONCILIATION_BYTES:
        raise RuntimeError("configure reconciliation receipt is oversized")
    return state


def _receipt_payload(path, lab_id):
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("invalid configure reconciliation receipt") from exc
    if (not isinstance(payload, dict) or payload.get("schema_version") != 1
            or payload.get("status") != "RECONCILIATION_REQUIRED"
            or payload.get("reason") != "configure_timeout"
            or payload.get("lab_id") != lab_id
            or payload.get("resource_reconciliation") != "unverified"
            or not isinstance(payload.get("cleanup"), dict)):
        raise RuntimeError("configure reconciliation receipt identity mismatch")
    validate_configure_timeout(payload.get("timeout_seconds"))
    return payload


def ensure_no_unresolved_reconciliation(lab, lab_id, *, require_root_owner=True):
    """Fail closed when a previous configure timeout awaits manual review."""
    path = Path(lab) / RECONCILIATION_FILENAME
    if _receipt_stat(path, require_root_owner=require_root_owner) is None:
        return False
    _receipt_payload(path, lab_id)
    raise RuntimeError("configure reconciliation required before retry")


def persist_configure_reconciliation(lab, lab_id, timeout, cleanup_evidence,
                                     *, require_root_owner=True, now=None):
    """Atomically persist timeout evidence while lifecycle locks are held."""
    timeout = validate_configure_timeout(timeout)
    if not VALID_LAB.fullmatch(lab_id):
        raise ValueError("invalid laboratory ID")
    if not isinstance(cleanup_evidence, dict):
        raise ValueError("invalid configure cleanup evidence")
    payload = {
        "schema_version": 1,
        "status": "RECONCILIATION_REQUIRED",
        "reason": "configure_timeout",
        "lab_id": lab_id,
        "timeout_seconds": timeout,
        "cleanup": cleanup_evidence,
        "resource_reconciliation": "unverified",
        "created_utc": (now or datetime.now(timezone.utc)).isoformat(),
    }
    json.dumps(payload, allow_nan=False)
    lab = Path(lab)
    if lab.is_symlink() or not lab.is_dir():
        raise RuntimeError("unsafe laboratory directory")
    path = lab / RECONCILIATION_FILENAME
    _receipt_stat(path, require_root_owner=require_root_owner)
    fd, temporary = tempfile.mkstemp(prefix=".configure-reconciliation-", dir=lab)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(lab, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def registry_ready_snapshot(lab_id):
    """Inspect private receipts as root, before dropping to the SSH user."""
    spec = importlib.util.spec_from_file_location("opla_configure_registry", HERE / "opla-registry.py")
    registry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(registry)
    records = registry.inspect(ROOT, lab_id)
    if (len(records) != 1 or records[0].get("lab") != lab_id
            or records[0].get("status") != "recorded"):
        status = records[0].get("status", "missing") if len(records) == 1 else "missing_or_ambiguous"
        raise RuntimeError(f"laboratory registry check failed: {status}; retain lab and inspect receipt/state as root")
    return records


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    lab_id = validate_arguments(argv)
    user = invoking_user()

    verify_trusted_code()

    lab = ROOT / lab_id

    if lab.is_symlink() or not lab.is_dir():
        raise RuntimeError("laboratory missing or unsafe")

    configure_timeout = configure_timeout_from_env()
    ensure_no_unresolved_reconciliation(lab, lab_id)

    locks = load_locks()

    # The order matches lab-lifecycle.py.
    with ExitStack() as stack:
        stack.enter_context(
            locks.lifecycle_lock(ROOT / ".opla-prune.lock")
        )
        stack.enter_context(
            locks.lifecycle_lock(lab / "maintenance.lock")
        )

        # A root-owned private snapshot stays readable through its inherited FD
        # after setuid; no receipt permissions or registry ownership are changed.
        snapshot = stack.enter_context(tempfile.TemporaryFile(mode="w+b"))
        snapshot.write(json.dumps(registry_ready_snapshot(lab_id)).encode())
        snapshot.flush()
        snapshot.seek(0)
        registry_fd = os.open(f"/proc/self/fd/{snapshot.fileno()}", os.O_RDONLY)
        stack.callback(os.close, registry_fd)

        # Locks and private registry inspection stay in the privileged parent.
        # The configuration itself executes as the original user.
        def drop_privileges():
            os.initgroups(user.pw_name, user.pw_gid)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)

        env = {
            "HOME": user.pw_dir,
            "USER": user.pw_name,
            "LOGNAME": user.pw_name,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LAB_DIR": str(lab),
        }

        # Optional SSH identity, if explicitly supplied through sudo.
        if "SSH_KEY" in os.environ:
            env["SSH_KEY"] = os.environ["SSH_KEY"]

        try:
            result = run_configure(
                ["/bin/bash", str(HERE / "opla-lab-configure.sh"), lab_id, lab_id, str(registry_fd)],
                cwd=str(HERE.parent), env=env, preexec_fn=drop_privileges,
                timeout=configure_timeout,
                pass_fds=(registry_fd,),
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            persist_configure_reconciliation(
                lab, lab_id, configure_timeout,
                getattr(exc, "cleanup_evidence", {}),
            )
            raise

        return result.returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        OSError,
        ValueError,
        RuntimeError,
        BlockingIOError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        sys.exit(2)
