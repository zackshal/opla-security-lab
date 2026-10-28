import importlib.util
import json
import math
import os
import signal
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

    def test_timeout_is_forwarded_and_reconciliation_blocks_retry(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            calls = []

            def fake_lock(path):
                from contextlib import nullcontext
                return nullcontext(8)

            def runner(*args, **kwargs):
                calls.append(kwargs)
                raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

            with patch.object(launcher, "verify_root"), \
                 patch.object(launcher, "verify_trusted_code"), \
                 patch.object(launcher, "load_locks", return_value=type(
                     "Locks", (), {"lifecycle_lock": staticmethod(fake_lock)})()):
                with self.assertRaises(subprocess.TimeoutExpired):
                    launcher.run_creation(root, Path("create.sh"), runner=runner, timeout=12)
                receipt = root / launcher.CREATE_RECONCILIATION_FILENAME
                self.assertEqual(json.loads(receipt.read_text())["status"],
                                 "RECONCILIATION_REQUIRED")
                with self.assertRaisesRegex(RuntimeError, "reconciliation required"):
                    launcher.run_creation(root, Path("create.sh"), runner=runner, timeout=12)
            self.assertEqual(calls[0]["timeout"], 12)

    def test_invalid_create_timeout_is_rejected_before_dispatch(self):
        for timeout in (True, False, 0, -1, math.nan, math.inf, 7201):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                launcher.validate_create_timeout(timeout)

    def test_owned_group_timeout_terminates_and_reaps(self):
        class Process:
            pid = 4455
            def __init__(self):
                self.waits = 0
            def wait(self, timeout=None):
                self.waits += 1
                if self.waits < 3:
                    raise subprocess.TimeoutExpired("create", timeout)
                return 137

        signals = []
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            launcher._run_owned(
                ["create"], env={}, pass_fds=(), timeout=1,
                popen_factory=lambda *a, **k: Process(),
                killpg=lambda pid, sig: signals.append((pid, sig)), grace=1,
            )
        self.assertEqual(signals, [(4455, signal.SIGTERM), (4455, signal.SIGKILL)])
        self.assertEqual(caught.exception.cleanup_evidence["status"], "reaped-after-kill")

    def test_malformed_runner_result_persists_reconciliation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from contextlib import nullcontext

            def fake_lock(path):
                return nullcontext(8)

            def runner(*args, **kwargs):
                return object()

            with patch.object(launcher, "verify_root"), \
                 patch.object(launcher, "verify_trusted_code"), \
                 patch.object(launcher, "load_locks", return_value=type(
                     "Locks", (), {"lifecycle_lock": staticmethod(fake_lock)})()):
                with self.assertRaises(ValueError):
                    launcher.run_creation(root, Path("create.sh"), runner=runner)
            receipt = root / launcher.CREATE_RECONCILIATION_FILENAME
            payload = json.loads(receipt.read_text())
            self.assertEqual(payload["cleanup"]["error_type"], "ValueError")

    def test_reconciliation_persistence_fsyncs_file_and_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.object(launcher.os, "fsync", wraps=launcher.os.fsync) as fsync:
                path = launcher.persist_create_reconciliation(root, 10, {})
            self.assertTrue(path.exists())
            self.assertGreaterEqual(fsync.call_count, 2)

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
