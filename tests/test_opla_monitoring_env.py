import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opla_monitoring_env", ROOT / "bin/opla_monitoring_env.py")
ENV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENV)


class MonitoringEnvMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.source = self.root / "monitoring.env"
        self.source.write_text("DB_PASSWORD=original-secret\n")
        self.source.chmod(0o600)
        self.destination = self.home / ".config/opla/monitoring.env"

    def test_migrates_once_with_private_permissions_and_exact_bytes(self):
        copied = ENV.migrate(self.source, self.destination, owner_uid=os.getuid(),
                             owner_gid=os.getgid(), home=self.home)
        self.assertTrue(copied)
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.destination.parent.stat().st_mode), 0o700)
        self.assertFalse(ENV.migrate(self.source, self.destination, owner_uid=os.getuid(),
                                     owner_gid=os.getgid(), home=self.home))

    def test_existing_destination_is_never_overwritten(self):
        self.destination.parent.mkdir(parents=True, mode=0o700)
        self.destination.write_text("DB_PASSWORD=chosen-secret\n")
        self.destination.chmod(0o600)
        self.assertFalse(ENV.migrate(self.source, self.destination, owner_uid=os.getuid(),
                                     owner_gid=os.getgid(), home=self.home))
        self.assertEqual(self.destination.read_text(), "DB_PASSWORD=chosen-secret\n")

    def test_rejects_symlink_hardlink_and_ambiguous_password(self):
        link = self.root / "link.env"
        link.symlink_to(self.source)
        with self.assertRaisesRegex(ValueError, "symlink"):
            ENV.migrate(link, self.destination, owner_uid=os.getuid(),
                        owner_gid=os.getgid(), home=self.home)
        (self.root / "alias.env").hardlink_to(self.source)
        with self.assertRaisesRegex(ValueError, "unsafe file identity"):
            ENV.migrate(self.root / "alias.env", self.destination, owner_uid=os.getuid(),
                        owner_gid=os.getgid(), home=self.home)
        (self.root / "alias.env").unlink()
        self.source.write_text("DB_PASSWORD=one\nDB_PASSWORD=two\n")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            ENV.migrate(self.source, self.destination, owner_uid=os.getuid(),
                        owner_gid=os.getgid(), home=self.home)


if __name__ == "__main__":
    unittest.main()
