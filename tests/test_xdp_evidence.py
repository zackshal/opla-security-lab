import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_xdp_evidence",
    ROOT / "bin/opla-xdp-evidence.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class XDPEvidenceTests(unittest.TestCase):

    def setUp(self):
        self.before = {
            "loaded": 1,
            "syn": 100,
            "pass": 100,
            "drop": 0,
            "map_full": 0,
            "fragment_drop": 0,
        }

    def test_real_counter_deltas(self):
        after = dict(self.before)
        after["syn"] = 125
        after["pass"] = 120
        after["drop"] = 5

        result = module.analyze(self.before, after)

        self.assertEqual(result["deltas"]["syn"], 25)
        self.assertEqual(result["deltas"]["drop"], 5)
        self.assertTrue(result["telemetry_collected"])
        self.assertIsNone(result["scan_detected"])

    def test_unloaded_xdp_rejected(self):
        after = dict(self.before)
        after["loaded"] = 0

        with self.assertRaises(ValueError):
            module.analyze(self.before, after)

    def test_counter_reset_rejected(self):
        after = dict(self.before)
        after["syn"] = 10

        with self.assertRaises(ValueError):
            module.analyze(self.before, after)

    def test_missing_counter_rejected(self):
        after = dict(self.before)
        del after["syn"]

        with self.assertRaises(ValueError):
            module.analyze(self.before, after)


if __name__ == "__main__":
    unittest.main()
