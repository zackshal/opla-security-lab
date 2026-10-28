import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_incident_report_test",
    ROOT / "bin/opla-incident-report.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class IncidentReportTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        self.root = Path(tmp.name)
        self.experiment = self.root / "scenario-syn-TEST1234"
        self.experiment.mkdir()

        interval = {
            "schema_version": 1,
            "clock_source": "victim",
            "start": "2026-10-27T13:00:00Z",
            "end": "2026-10-27T13:00:10Z",
            "source_ip": "100.64.0.2",
            "target_ip": "100.64.0.3",
        }
        (self.experiment / "interval.json").write_text(
            json.dumps(interval)
        )
        (self.experiment / "before.json").write_text(
            json.dumps({"loaded": 1, "syn": 100, "drop": 0})
        )
        (self.experiment / "after.json").write_text(
            json.dumps({"loaded": 1, "syn": 150, "drop": 30})
        )

        self.scan = self.root / "events.jsonl"
        self.event = {
            "timestamp": 1793106005,
            "source_ip": "100.64.0.2",
            "destination_ip": "100.64.0.3",
            "event": "tcp_port_scan_suspected",
            "distinct_ports": 8,
            "sample_ports": [20, 21, 22, 23, 24, 25, 26, 27],
            "action": "alert",
        }

    def test_missing_logs_remain_unavailable(self):
        report = module.build_report(self.experiment)
        self.assertEqual(report["suricata"]["status"], "unavailable")
        self.assertEqual(
            report["scan_detector"]["status"], "unavailable"
        )
        self.assertEqual(
            report["counters"]["metrics"]["xdp"]["syn"], 50
        )

    def test_scan_event_matching(self):
        from datetime import datetime, timezone
        self.event["timestamp"] = int(
            datetime(2026, 10, 27, 13, 0, 5,
                     tzinfo=timezone.utc).timestamp()
        )
        self.scan.write_text(json.dumps(self.event) + "\n")

        report = module.build_report(
            self.experiment, scan_path=self.scan
        )
        self.assertEqual(
            report["scan_detector"]["matching_events"], 1
        )
        self.assertEqual(report["attack_attribution"], "unverified")

    def test_unrelated_scan_event_excluded(self):
        from datetime import datetime, timezone
        self.event["timestamp"] = int(
            datetime(2026, 10, 27, 13, 0, 5,
                     tzinfo=timezone.utc).timestamp()
        )
        self.event["source_ip"] = "100.64.0.5"
        self.scan.write_text(json.dumps(self.event) + "\n")

        result = module.build_report(
            self.experiment, scan_path=self.scan
        )
        self.assertEqual(
            result["scan_detector"]["matching_events"], 0
        )

    def test_missing_interval_rejected(self):
        (self.experiment / "interval.json").unlink()
        with self.assertRaises(ValueError):
            module.build_report(self.experiment)


if __name__ == "__main__":
    unittest.main()
