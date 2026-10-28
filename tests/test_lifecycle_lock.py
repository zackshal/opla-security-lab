import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_lifecycle_lock",
    ROOT / "bin" / "opla-lifecycle-lock.py",
)
lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lock)


class LifecycleLockTests(unittest.TestCase):

    def test_safe_lock_opens_and_closes(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "global.lock"

            with patch.object(lock, "validate") as check:
                with lock.lifecycle_lock(path) as fd:
                    self.assertTrue(path.is_file())
                    self.assertEqual(os.fstat(fd).st_nlink, 1)
                    self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)

                self.assertGreaterEqual(check.call_count, 2)

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target"
            target.write_text("DO NOT CHANGE")
            (root / "global.lock").symlink_to(target)

            with self.assertRaises(OSError):
                lock.open_lock(root / "global.lock")

            self.assertEqual(target.read_text(), "DO NOT CHANGE")

    def test_hardlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = root / "original"
            original.touch(mode=0o600)
            os.link(original, root / "global.lock")

            with self.assertRaises(lock.UnsafeLock):
                lock.open_lock(root / "global.lock")

    def test_world_writable_lock_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "global.lock"
            path.touch()
            path.chmod(0o666)

            with self.assertRaises(lock.UnsafeLock):
                lock.open_lock(path)

    def test_concurrent_lock_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "global.lock"

            with patch.object(lock, "validate"):
                with lock.lifecycle_lock(path):
                    code = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(0)
sys.exit(1)
"""
                    result = subprocess.run(
                        ["python3", "-c", code, str(path)],
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()


class LifecycleIntegrationTests(unittest.TestCase):

    def test_lab_lifecycle_uses_safe_locks(self):
        source = (ROOT / "bin" / "lab-lifecycle.py").read_text()

        self.assertIn(
            "lifecycle_locks.lifecycle_lock(",
            source,
        )

        self.assertIn(
            "lab / 'maintenance.lock'",
            source,
        )

        self.assertNotIn(
            "'.opla-prune.lock').open('a')",
            source,
        )

        self.assertNotIn(
            "'maintenance.lock').open('a')",
            source,
        )
