"""Isolated subprocess tests for OPLA creation lock inheritance."""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "bin"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, BIN / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



PROBE = """
import importlib.util
import os
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "fd_checker", sys.argv[1]
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

module.verify_pair(
    Path(sys.argv[2]),
    int(sys.argv[3]),
    int(sys.argv[4]),
    expected_uid=os.geteuid(),
)
"""


class CreateFDIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="opla-create-fd-test-"
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_probe(self, global_fd, create_fd, pass_fds=None):
        if pass_fds is None:
            pass_fds = (global_fd, create_fd)

        env = os.environ.copy()
        env.update({
            "OPLA_PROBE": PROBE,
            "OPLA_CHECKER": str(
                BIN / "opla-create-lock-check.py"
            ),
            "OPLA_TEST_ROOT": str(self.root),
            "OPLA_GLOBAL_FD": str(global_fd),
            "OPLA_LOCAL_FD": str(create_fd),
        })

        return subprocess.run(
            [
                "bash",
                "-c",
                'python3 -c "$OPLA_PROBE" '
                '"$OPLA_CHECKER" "$OPLA_TEST_ROOT" '
                '"$OPLA_GLOBAL_FD" "$OPLA_LOCAL_FD"',
            ],
            env=env,
            pass_fds=pass_fds,
            capture_output=True,
            text=True,
            check=False,
        )

    def locked_pair(self, stack):
        import fcntl

        fds = []

        for filename in (".opla-prune.lock", "create.lock"):
            path = self.root / filename

            fd = os.open(
                path,
                os.O_CREAT | os.O_RDWR |
                os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )

            stack.callback(os.close, fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            fds.append(fd)

        return tuple(fds)

    def test_valid_inherited_fds(self):
        with ExitStack() as stack:
            fds = self.locked_pair(stack)
            result = self.run_probe(*fds)

            self.assertEqual(
                result.returncode, 0, result.stderr
            )

    def test_swapped_fds_rejected(self):
        with ExitStack() as stack:
            global_fd, create_fd = self.locked_pair(stack)
            result = self.run_probe(
                create_fd, global_fd
            )

            self.assertNotEqual(result.returncode, 0)

    def test_unlocked_fds_rejected(self):
        with ExitStack() as stack:
            self.locked_pair(stack)

        global_fd = os.open(
            self.root / ".opla-prune.lock", os.O_RDONLY
        )
        create_fd = os.open(
            self.root / "create.lock", os.O_RDONLY
        )

        try:
            result = self.run_probe(global_fd, create_fd)
            self.assertNotEqual(result.returncode, 0)
        finally:
            os.close(global_fd)
            os.close(create_fd)

    def test_fds_not_forwarded_to_bash_rejected(self):
        with ExitStack() as stack:
            global_fd, create_fd = self.locked_pair(stack)
            result = self.run_probe(
                global_fd,
                create_fd,
                pass_fds=(),
            )

            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
