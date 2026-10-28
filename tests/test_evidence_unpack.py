import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_evidence_unpack_test",
    ROOT / "bin/opla-evidence-unpack.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceUnpackTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "export.json"

    def write_export(self, **changes):
        data = {
            "source": "scan",
            "status": "captured",
            "coverage": "partial",
            "records": [{"timestamp": 123, "event": "test"}],
        }
        data.update(changes)
        self.source.write_text(json.dumps(data))

    def test_captured_records(self):
        self.write_export()
        meta = module.unpack(self.source, self.root, "scan")

        self.assertEqual(meta["coverage"], "partial")
        self.assertEqual(meta["exported_records"], 1)
        self.assertEqual(
            json.loads(
                (self.root / "events.jsonl").read_text().strip()
            )["timestamp"],
            123,
        )

    def test_unavailable_source(self):
        self.write_export(status="unavailable", records=[])
        meta = module.unpack(self.source, self.root, "scan")

        self.assertEqual(meta["status"], "unavailable")
        self.assertFalse((self.root / "events.jsonl").exists())

    def test_wrong_source_rejected(self):
        self.write_export(source="suricata")
        with self.assertRaises(ValueError):
            module.unpack(self.source, self.root, "scan")

    def test_invalid_record_rejected(self):
        self.write_export(records=["not an object"])
        with self.assertRaises(ValueError):
            module.unpack(self.source, self.root, "scan")

    def test_symlink_export_rejected(self):
        original = self.root / "original.json"
        original.write_text("{}")
        self.source.symlink_to(original)
        with self.assertRaises(ValueError):
            module.unpack(self.source, self.root, "scan")


if __name__ == "__main__":
    unittest.main()
