"""Negative tests for OPLA image verification."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/opla-image-verify.py"

spec = importlib.util.spec_from_file_location("opla_image_verify", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ImageVerifierTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.images = Path(self.temp.name)
        self.name = "debian-12-xdp.qcow2"

        (self.images / self.name).write_bytes(b"test-image")
        (self.images / (self.name + ".role")).write_text("victim\n")

        self.images_patch = patch.object(verifier, "IMAGES", self.images)
        self.images_patch.start()
        self.addCleanup(self.images_patch.stop)

    def test_checksum_mismatch_is_blocked(self):
        (self.images / (self.name + ".sha256")).write_text(
            "0" * 64 + f"  {self.name}\n"
        )

        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            verifier.verify("victim", self.name, 1024)

    def test_role_mismatch_is_blocked(self):
        import hashlib

        digest = hashlib.sha256(b"test-image").hexdigest()
        (self.images / (self.name + ".sha256")).write_text(
            f"{digest}  {self.name}\n"
        )
        (self.images / (self.name + ".role")).write_text("attacker\n")

        with self.assertRaisesRegex(ValueError, "role mismatch"):
            verifier.verify("victim", self.name, 1024)


if __name__ == "__main__":
    unittest.main()
