import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_experiment_report",
    ROOT / "bin/opla-experiment-report.py",
)
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


class ExperimentReportTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.folder = self.root / "scenario-syn-TEST1234"
        self.folder.mkdir()

        before = {
            "loaded": 1,
            "syn": 100,
            "pass": 100,
            "drop": 0,
            "map_full": 0,
            "fragment_drop": 0,
        }
        after = dict(before)
        after.update(syn=150, **{"pass": 145, "drop": 5})

        (self.folder / "before.json").write_text(json.dumps(before))
        (self.folder / "after.json").write_text(json.dumps(after))
        (self.folder / "generator-exit.txt").write_text("0\n")

        patcher = patch.object(reporter, "REPORTS", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_valid_report(self):
        result = reporter.build_report(self.folder)
        self.assertEqual(result["xdp"]["deltas"]["syn"], 50)
        self.assertEqual(result["xdp"]["deltas"]["drop"], 5)
        self.assertIsNone(result["attack_detected"])
        self.assertFalse(result["actual_execution_by_reporter"])

    def test_failed_generator_is_not_reported_successful(self):
        (self.folder / "generator-exit.txt").write_text("1\n")
        result = reporter.build_report(self.folder)
        self.assertIsNone(result["traffic_generated"])

    def test_missing_snapshot_rejected(self):
        (self.folder / "after.json").unlink()
        with self.assertRaises(ValueError):
            reporter.build_report(self.folder)

    def test_symlink_snapshot_rejected(self):
        snapshot = self.folder / "before.json"
        target = self.root / "other.json"
        target.write_bytes(snapshot.read_bytes())
        snapshot.unlink()
        snapshot.symlink_to(target)

        with self.assertRaises(ValueError):
            reporter.build_report(self.folder)

    def test_invalid_exit_code_rejected(self):
        (self.folder / "generator-exit.txt").write_text("999\n")
        with self.assertRaises(ValueError):
            reporter.build_report(self.folder)


if __name__ == "__main__":
    unittest.main()
