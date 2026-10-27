"""P14.2b offline review staging: deliberately unprivileged."""
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "bin" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bundle = load("opla-release-bundle.py", "opla_bundle_for_stage_test")
stager = load("opla-release-stage.py", "opla_release_stage_test")


class StageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "source"
        for name in ("Makefile", "bin/opla-create-launcher.py",
                     "bin/opla-lab-configure-launcher.py", "bin/create-lab.sh",
                     "bin/opla-lifecycle-lock.py"):
            p = self.source / name
            p.parent.mkdir(exist_ok=True, parents=True)
            p.write_text("example\n")
        self.archive = self.root / "release.tar.gz"
        bundle.build(self.source, self.archive)
        self.sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.destination = self.root / "review"

    def staged(self, hash_value=None):
        with patch.object(stager.os, "geteuid", return_value=1000), patch.object(
            stager.os, "getuid", return_value=os.getuid()
        ):
            return stager.stage(self.archive, self.destination, hash_value or self.sha)

    def test_stage_review_tree(self):
        self.assertEqual(self.staged(), 5)
        self.assertTrue((self.destination / "bin/create-lab.sh").is_file())
        report = json.loads((self.destination / "REVIEW.json").read_text())
        self.assertEqual(report["bundle_sha256"], self.sha)

    def test_mismatched_approval_blocks(self):
        with self.assertRaisesRegex(ValueError, "approved SHA-256"):
            self.staged("0" * 64)
        self.assertFalse(self.destination.exists())

    def test_root_forbidden(self):
        with patch.object(stager.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "root execution forbidden"):
                stager.stage(self.archive, self.destination, self.sha)

    def test_existing_destination_not_overwritten(self):
        self.destination.mkdir()
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.staged()

    def test_symlink_parent_rejected(self):
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            with patch.object(stager.os, "geteuid", return_value=1000):
                stager.stage(self.archive, self.root / "link" / "review", self.sha)

    def test_corrupt_bundle_rejected(self):
        with self.archive.open("ab") as f:
            f.write(b"junk")
        with self.assertRaisesRegex(ValueError, "approved SHA-256"):
            self.staged()


if __name__ == "__main__":
    unittest.main()
