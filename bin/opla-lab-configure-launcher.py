#!/usr/bin/env python3
"""Hold OPLA lifecycle locks while configuring a lab as the invoking user."""

import importlib.util
import os
import pwd
import re
import subprocess
import stat
import sys
from contextlib import ExitStack
from pathlib import Path

ROOT = Path("/var/lib/opla")
HERE = Path(__file__).resolve().parent
VALID_LAB = re.compile(r"lab-[A-Za-z0-9]{4,32}\Z")



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


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    lab_id = validate_arguments(argv)
    user = invoking_user()

    verify_trusted_code()

    lab = ROOT / lab_id

    if lab.is_symlink() or not lab.is_dir():
        raise RuntimeError("laboratory missing or unsafe")

    locks = load_locks()

    # The order matches lab-lifecycle.py.
    with ExitStack() as stack:
        stack.enter_context(
            locks.lifecycle_lock(ROOT / ".opla-prune.lock")
        )
        stack.enter_context(
            locks.lifecycle_lock(lab / "maintenance.lock")
        )

        # Keep the privileged operation limited to lock ownership.
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

        result = subprocess.run(
            [
                "/bin/bash",
                str(HERE / "opla-lab-configure.sh"),
                lab_id,
                lab_id,
            ],
            cwd=str(HERE.parent),
            env=env,
            preexec_fn=drop_privileges,
            check=False,
        )

        return result.returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        OSError,
        ValueError,
        RuntimeError,
        BlockingIOError,
    ) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        sys.exit(2)
