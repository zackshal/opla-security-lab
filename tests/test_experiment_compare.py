import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_experiment_compare_test",
    ROOT / "bin/opla-experiment-compare.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExperimentCompareTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.folder = self.root / "scenario-syn-TEST1234"
        self.folder.mkdir()

        before = {
            "loaded": 1, "mode": "native",
            "syn": 100, "pass": 100, "drop": 0,
            "map_full": 0, "fragment_drop": 0,
        }
        after = {
            **before,
            "syn": 200, "pass": 130, "drop": 70,
        }

        (self.folder / "before.json").write_text(json.dumps(before))
        (self.folder / "after.json").write_text(json.dumps(after))
        (self.folder / "generator-exit.txt").write_text("0\n")
        (self.folder / "context.txt").write_text(
            "LAB_DIR=/var/lib/opla/lab-TEST1234\n"
            + "a" * 64 + "  xdp/xdp_ddos_protect.c\n"
        )

        patcher = patch.object(module.reporter, "REPORTS", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_valid_experiment(self):
        result = module.compare(self.folder)
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["lab_id"], "lab-TEST1234")
        self.assertEqual(result["source_sha256"], "a" * 64)
        self.assertEqual(result["xdp_mode"], "native")
        self.assertEqual(result["drop_percent"], 70.0)

    def test_unloaded_xdp_is_invalid(self):
        path = self.folder / "before.json"
        data = json.loads(path.read_text())
        data["loaded"] = 0
        path.write_text(json.dumps(data))

        self.assertEqual(module.compare(self.folder)["status"], "invalid")

    def test_counter_mismatch(self):
        path = self.folder / "after.json"
        data = json.loads(path.read_text())
        data["syn"] = 201
        path.write_text(json.dumps(data))

        self.assertEqual(
            module.compare(self.folder)["status"],
            "counter_mismatch",
        )

    def test_generator_failure(self):
        (self.folder / "generator-exit.txt").write_text("1\n")
        self.assertEqual(
            module.compare(self.folder)["status"],
            "generator_failed",
        )

    def test_attachment_mode_change(self):
        path = self.folder / "after.json"
        data = json.loads(path.read_text())
        data["mode"] = "generic"
        path.write_text(json.dumps(data))

        self.assertEqual(module.compare(self.folder)["status"], "invalid")

    def test_collect(self):
        rows = module.collect(self.root)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "valid")


if __name__ == "__main__":
    unittest.main()
