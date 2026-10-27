#!/usr/bin/env python3
"""Verified entry point for OPLA laboratory creation."""

import importlib.util
import os
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = Path("/var/lib/opla")


def load_locks():
    path = HERE / "opla-lifecycle-lock.py"
    spec = importlib.util.spec_from_file_location(
        "opla_create_locks", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


locks = load_locks()


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


def run_creation(root, script, runner=subprocess.run):
    """Hold both lifecycle locks throughout script execution."""
    verify_root(root)

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

        result = runner(
            ["bash", str(script)],
            env=env,
            pass_fds=(global_fd, create_fd),
            check=False,
        )
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
