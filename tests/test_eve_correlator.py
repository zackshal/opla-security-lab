import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_eve_correlator_test",
    ROOT / "bin/opla-eve-correlator.py",
)
eve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eve)


class EVECorrelatorTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "eve.json"

        self.base = {
            "event_type": "alert",
            "timestamp": "2026-10-27T13:00:05+00:00",
            "src_ip": "100.64.0.2",
            "dest_ip": "100.64.0.3",
            "proto": "TCP",
            "dest_port": 80,
            "alert": {
                "signature_id": 100001,
                "signature": "Test SYN alert",
                "severity": 2,
                "action": "allowed",
            },
        }

    def analyze(self):
        return eve.correlate_eve(
            self.path,
            "2026-10-27T13:00:00Z",
            "2026-10-27T13:00:10Z",
            "100.64.0.2",
            "100.64.0.3",
        )

    def test_matching_alert(self):
        self.path.write_text(json.dumps(self.base) + "\n")
        result = self.analyze()
        self.assertEqual(result["matching_alerts"], 1)
        self.assertEqual(result["alerts"][0]["signature_id"], 100001)
        self.assertEqual(result["causal_attribution"], "unverified")

    def test_unrelated_source_excluded(self):
        row = dict(self.base, src_ip="100.64.0.4")
        self.path.write_text(json.dumps(row) + "\n")
        self.assertEqual(self.analyze()["matching_alerts"], 0)

    def test_outside_interval_excluded(self):
        row = dict(self.base, timestamp="2026-10-27T13:01:00Z")
        self.path.write_text(json.dumps(row) + "\n")
        self.assertEqual(self.analyze()["matching_alerts"], 0)

    def test_malformed_line_counted(self):
        self.path.write_text(
            "not json\n" + json.dumps(self.base) + "\n"
        )
        result = self.analyze()
        self.assertEqual(result["malformed_records"], 1)
        self.assertEqual(result["matching_alerts"], 1)

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            eve.parse_time("2026-10-27T13:00:00")

    def test_symlink_rejected(self):
        actual = self.path.with_name("original.json")
        actual.write_text(json.dumps(self.base))
        self.path.symlink_to(actual)
        with self.assertRaises(ValueError):
            self.analyze()


if __name__ == "__main__":
    unittest.main()
