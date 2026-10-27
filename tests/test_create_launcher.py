import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_create_launcher",
    ROOT / "bin" / "opla-create-launcher.py",
)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class CreateLauncherTests(unittest.TestCase):

    def test_untrusted_root_blocks_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o777)

            calls = []

            def runner(*args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess([], 0)

            with self.assertRaises(RuntimeError):
                launcher.run_creation(
                    root, Path("unused.sh"), runner=runner
                )

            self.assertEqual(calls, [])

    def test_both_locks_held_during_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            calls = []
            held = []

            def fake_lock(path):
                from contextlib import contextmanager

                @contextmanager
                def context():
                    held.append(path.name)
                    try:
                        yield 8 if path.name == ".opla-prune.lock" else 9
                    finally:
                        held.remove(path.name)

                return context()

            def runner(*args, **kwargs):
                calls.append(args)
                self.assertEqual(
                    held,
                    [".opla-prune.lock", "create.lock"],
                )
                self.assertEqual(
                    kwargs["env"]["OPLA_VERIFIED_CREATE_LAUNCHER"],
                    "1",
                )
                self.assertEqual(kwargs["pass_fds"], (8, 9))
                self.assertEqual(kwargs["env"]["OPLA_CREATE_GLOBAL_FD"], "8")
                self.assertEqual(kwargs["env"]["OPLA_CREATE_LOCAL_FD"], "9")
                return subprocess.CompletedProcess([], 17)

            with patch.object(
                launcher, "verify_root"
            ), patch.object(
                launcher, "verify_trusted_code"
            ), patch.object(
                launcher, "load_locks",
                return_value=type("Locks", (), {"lifecycle_lock": staticmethod(fake_lock)})()
            ):
                result = launcher.run_creation(
                    root, Path("unused.sh"), runner=runner
                )

            self.assertEqual(result, 17)
            self.assertEqual(len(calls), 1)
            self.assertEqual(held, [])

    def test_untrusted_code_blocks_before_import_and_runner(self):
        with patch.object(launcher, "verify_root"), patch.object(
            launcher, "verify_trusted_code", side_effect=RuntimeError("untrusted source")
        ), patch.object(launcher, "load_locks") as locks, patch.object(
            launcher.subprocess, "run"
        ) as runner:
            with self.assertRaisesRegex(RuntimeError, "untrusted source"):
                launcher.run_creation(Path("/var/lib/opla"), Path("unused.sh"))
            locks.assert_not_called()
            runner.assert_not_called()

    def test_make_uses_verified_launcher(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn(
            "sudo python3 bin/opla-create-launcher.py",
            makefile,
        )

    def test_direct_script_requires_launcher(self):
        source = (
            ROOT / "bin" / "create-lab.sh"
        ).read_text()

        self.assertIn(
            "OPLA_VERIFIED_CREATE_LAUNCHER",
            source,
        )
        self.assertNotIn(
            "exec 8>/var/lib/opla/.opla-prune.lock",
            source,
        )


if __name__ == "__main__":
    unittest.main()


class RootPathSecurityTests(unittest.TestCase):

    def test_parent_directory_is_checked(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / "parent"
            parent.mkdir()
            root = parent / "opla"
            root.mkdir()

            parent.chmod(0o777)

            with self.assertRaises(RuntimeError):
                launcher.verify_root(root)

    def test_missing_root_is_not_created(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "missing-opla-root"

            with patch.object(launcher, "ROOT", missing):
                with patch.object(launcher.os, "geteuid", return_value=0):
                    with self.assertRaises(RuntimeError):
                        launcher.main()

            self.assertFalse(missing.exists())
