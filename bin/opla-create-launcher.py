#!/usr/bin/env python3
"""Verified entry point for OPLA laboratory creation."""

import importlib.util
import json
import math
import os
import signal
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = Path("/var/lib/opla")
DEFAULT_CREATE_TIMEOUT = 3600
MAX_CREATE_TIMEOUT = 7200
CREATE_TERMINATION_GRACE = 5
CREATE_RECONCILIATION_FILENAME = "create-reconciliation.json"


def load_locks():
    path = HERE / "opla-lifecycle-lock.py"
    spec = importlib.util.spec_from_file_location(
        "opla_create_locks", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



def verify_root(root):
    import stat

    root = Path(root)

    if not root.is_absolute() or ".." in root.parts:
        raise RuntimeError("unsafe OPLA root path")

    components = [root, *root.parents]

    for component in components:
        try:
            st = component.lstat()
        except OSError as exc:
            raise RuntimeError(
                f"cannot inspect trusted directory: {component}"
            ) from exc

        if not stat.S_ISDIR(st.st_mode):
            raise RuntimeError(
                f"not a trusted directory: {component}"
            )

        if st.st_uid != 0:
            raise RuntimeError(
                f"directory not root-owned: {component}"
            )

        if st.st_mode & 0o022:
            raise RuntimeError(
                f"directory is writable by others: {component}"
            )


def verify_trusted_code():
    """Check installed code before importing auxiliary privileged modules."""
    import stat

    project = HERE.parent
    for directory in (project, *project.parents, HERE):
        st = directory.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022):
            raise RuntimeError(f"untrusted source directory: {directory}")

    for name in (
        "opla-create-launcher.py", "opla-lifecycle-lock.py", "create-lab.sh",
    ):
        path = HERE / name
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022 or st.st_nlink != 1):
            raise RuntimeError(f"untrusted privileged source: {path}")


def validate_create_timeout(timeout):
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0
            or timeout > MAX_CREATE_TIMEOUT):
        raise ValueError(
            f"create timeout must be finite, positive and <= {MAX_CREATE_TIMEOUT}s"
        )
    return timeout


def _run_owned(argv, *, env, pass_fds, timeout, grace=CREATE_TERMINATION_GRACE,
               popen_factory=None, killpg=os.killpg):
    validate_create_timeout(timeout)
    dispatch = subprocess.Popen if popen_factory is None else popen_factory
    process = dispatch(argv, env=env, pass_fds=pass_fds, start_new_session=True)
    try:
        return subprocess.CompletedProcess(argv, process.wait(timeout=timeout))
    except (subprocess.TimeoutExpired, OSError) as exc:
        cleanup = {"status": "unknown", "term_sent": False, "kill_sent": False}
        try:
            killpg(process.pid, signal.SIGTERM)
            cleanup["term_sent"] = True
        except ProcessLookupError:
            cleanup["status"] = "already-exited"
        except OSError as error:
            cleanup["term_error_type"] = type(error).__name__
        try:
            process.wait(timeout=grace)
            cleanup["status"] = "reaped-after-term"
        except subprocess.TimeoutExpired:
            try:
                killpg(process.pid, signal.SIGKILL)
                cleanup["kill_sent"] = True
            except ProcessLookupError:
                cleanup["status"] = "already-exited"
            except OSError as error:
                cleanup["kill_error_type"] = type(error).__name__
            try:
                process.wait()
                cleanup["status"] = "reaped-after-kill"
            except OSError as error:
                cleanup["reap_error_type"] = type(error).__name__
        except OSError as error:
            cleanup["wait_error_type"] = type(error).__name__
            try:
                killpg(process.pid, signal.SIGKILL)
                cleanup["kill_sent"] = True
            except OSError as kill_error:
                cleanup["kill_error_type"] = type(kill_error).__name__
            try:
                process.wait()
                cleanup["status"] = "reaped-after-error"
            except OSError as reap_error:
                cleanup["reap_error_type"] = type(reap_error).__name__
        exc.cleanup_evidence = cleanup
        raise


def _reconciliation_path(root):
    return Path(root) / CREATE_RECONCILIATION_FILENAME


def ensure_no_create_reconciliation(root):
    path = _reconciliation_path(root)
    if path.exists() or path.is_symlink():
        raise RuntimeError("create reconciliation required before retry")


def persist_create_reconciliation(root, timeout, cleanup_evidence):
    path = _reconciliation_path(root)
    payload = {
        "schema_version": 1,
        "status": "RECONCILIATION_REQUIRED",
        "reason": "create_dispatch_timeout_or_error",
        "timeout_seconds": timeout,
        "cleanup": cleanup_evidence if isinstance(cleanup_evidence, dict) else {},
    }
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return path


def run_creation(root, script, runner=None, *, timeout=DEFAULT_CREATE_TIMEOUT,
                 popen_factory=None, killpg=os.killpg):
    """Hold both lifecycle locks throughout script execution."""
    validate_create_timeout(timeout)
    verify_root(root)
    verify_trusted_code()
    ensure_no_create_reconciliation(root)
    locks = load_locks()

    with ExitStack() as stack:
        global_fd = stack.enter_context(
            locks.lifecycle_lock(root / ".opla-prune.lock")
        )
        create_fd = stack.enter_context(
            locks.lifecycle_lock(root / "create.lock")
        )

        env = os.environ.copy()
        env["OPLA_VERIFIED_CREATE_LAUNCHER"] = "1"
        env["OPLA_CREATE_GLOBAL_FD"] = str(global_fd)
        env["OPLA_CREATE_LOCAL_FD"] = str(create_fd)

        command = ["bash", str(script)]
        try:
            if runner is None:
                result = _run_owned(
                    command, env=env, pass_fds=(global_fd, create_fd),
                    timeout=timeout, popen_factory=popen_factory, killpg=killpg,
                )
            else:
                result = runner(
                    command, env=env, pass_fds=(global_fd, create_fd),
                    check=False, timeout=timeout,
                )
                if type(getattr(result, "returncode", None)) is not int:
                    raise ValueError("create runner returned an invalid exit status")
        except Exception as exc:
            cleanup = getattr(exc, "cleanup_evidence", {})
            if not isinstance(cleanup, dict):
                cleanup = {}
            cleanup = {**cleanup, "error_type": type(exc).__name__}
            persist_create_reconciliation(
                root, timeout, cleanup)
            raise
        return result.returncode


def main():
    if os.geteuid() != 0:
        raise RuntimeError("root required")

    # Fail closed: provisioning the OPLA root is not a creation action.
    # Never create or replace the lifecycle root implicitly.
    verify_root(ROOT)

    script = HERE / "create-lab.sh"
    return run_creation(ROOT, script)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        sys.exit(2)
