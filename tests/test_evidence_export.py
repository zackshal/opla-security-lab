import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_evidence_export_test",
    ROOT / "security/evidence/export.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceExportTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "events.jsonl"
        self.paths = {"scan": self.path}

    def test_valid_events(self):
        self.path.write_text(
            json.dumps({"timestamp": 1, "event": "test"}) + "\n"
        )
        result = module.export("scan", self.paths)
        self.assertEqual(result["status"], "captured")
        self.assertEqual(len(result["records"]), 1)
        self.assertFalse(result["truncated"])

    def test_missing_log(self):
        result = module.export("scan", self.paths)
        self.assertEqual(result["status"], "unavailable")

    def test_truncated_log(self):
        self.path.write_text(
            "".join(json.dumps({"id": i}) + "\n" for i in range(100))
        )
        result = module.export("scan", self.paths, limit=128)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["coverage"], "partial")
        self.assertGreater(len(result["records"]), 0)

    def test_malformed_event_counted(self):
        self.path.write_text('invalid\n{"event":"ok"}\n')
        result = module.export("scan", self.paths)
        self.assertEqual(result["malformed_records"], 1)
        self.assertEqual(len(result["records"]), 1)

    def test_arbitrary_source_rejected(self):
        with self.assertRaises(ValueError):
            module.export("other", self.paths)

    def test_invalid_limit_rejected(self):
        with self.assertRaises(ValueError):
            module.export("scan", self.paths, limit=2 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
