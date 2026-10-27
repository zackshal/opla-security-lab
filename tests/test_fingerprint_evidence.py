import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_fp_evidence_test",
    ROOT / "bin/opla-fingerprint-evidence.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FingerprintEvidenceTests(unittest.TestCase):

    def setUp(self):
        self.before = {
            "loaded": 1,
            "program_id": 42,
            "program_tag": "abc123",
            "attachment_mode": "native",
            "loaded_object_identity_verified": True,
            "load_receipt": {
                "object_sha256": "a" * 64,
                "build_manifest_sha256": "b" * 64,
            },
        }

    def test_verified(self):
        result = module.verify(self.before, dict(self.before))
        self.assertEqual(result["status"], "verified")

    def test_program_changed(self):
        after = dict(self.before, program_id=43)
        result = module.verify(self.before, after)
        self.assertEqual(result["status"], "invalid")

    def test_receipt_not_verified(self):
        after = dict(
            self.before,
            loaded_object_identity_verified=False,
        )
        result = module.verify(self.before, after)
        self.assertEqual(result["status"], "unverified")

    def test_object_changed(self):
        after = dict(
            self.before,
            load_receipt={
                "object_sha256": "c" * 64,
                "build_manifest_sha256": "b" * 64,
            },
        )
        self.assertEqual(
            module.verify(self.before, after)["status"],
            "invalid",
        )

    def test_legacy_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            result = module.verify_directory(Path(directory))
            self.assertEqual(result["status"], "unverified")


if __name__ == "__main__":
    unittest.main()
