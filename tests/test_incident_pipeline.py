import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exporter = load("pipeline_exporter", "security/evidence/export.py")
unpacker = load("pipeline_unpacker", "bin/opla-evidence-unpack.py")
reporter = load("pipeline_reporter", "bin/opla-incident-report.py")


class IncidentPipelineTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.experiment = self.root / "scenario-syn-OFFLINE"
        self.experiment.mkdir()

        interval = {
            "schema_version": 1,
            "clock_source": "victim",
            "start": "2026-10-27T13:00:00Z",
            "end": "2026-10-27T13:00:10Z",
            "source_ip": "100.64.0.2",
            "target_ip": "100.64.0.3",
        }

        before = {
            "loaded": 1,
            "syn": 100,
            "pass": 80,
            "drop": 20,
        }

        after = {
            "loaded": 1,
            "syn": 150,
            "pass": 90,
            "drop": 60,
        }

        for name, data in (
            ("interval.json", interval),
            ("before.json", before),
            ("after.json", after),
        ):
            (self.experiment / name).write_text(json.dumps(data))

    def export_and_unpack(self, kind, source, limit=None):
        kwargs = {"paths": {kind: source}}
        if limit is not None:
            kwargs["limit"] = limit

        captured = exporter.export(kind, **kwargs)
        export_file = self.root / f"{kind}-export.json"
        export_file.write_text(json.dumps(captured))

        return unpacker.unpack(
            export_file, self.experiment, kind
        )

    def test_both_detectors_in_one_report(self):
        eve_source = self.root / "source-eve.json"
        scan_source = self.root / "source-scan.jsonl"

        eve_alert = {
            "event_type": "alert",
            "timestamp": "2026-10-27T13:00:05Z",
            "src_ip": "100.64.0.2",
            "dest_ip": "100.64.0.3",
            "proto": "TCP",
            "dest_port": 80,
            "alert": {
                "signature_id": 100001,
                "signature": "Offline test",
                "action": "allowed",
            },
        }

        scan_alert = {
            "timestamp": int(
                datetime(
                    2026, 10, 27, 13, 0, 5,
                    tzinfo=timezone.utc,
                ).timestamp()
            ),
            "source_ip": "100.64.0.2",
            "destination_ip": "100.64.0.3",
            "event": "tcp_port_scan_suspected",
            "distinct_ports": 8,
            "sample_ports": [20, 21, 22, 23, 24, 25, 26, 27],
            "action": "alert",
        }

        eve_source.write_text(json.dumps(eve_alert) + "\n")
        scan_source.write_text(json.dumps(scan_alert) + "\n")

        self.export_and_unpack("suricata", eve_source)
        self.export_and_unpack("scan", scan_source)

        result = reporter.build_report(
            self.experiment,
            eve_path=self.experiment / "eve.json",
            scan_path=self.experiment / "events.jsonl",
        )

        self.assertEqual(
            result["counters"]["metrics"]["xdp"]["drop"], 40
        )
        self.assertEqual(result["suricata"]["matching_alerts"], 1)
        self.assertEqual(
            result["scan_detector"]["matching_events"], 1
        )
        self.assertEqual(
            result["evidence_exports"]["suricata"]["status"],
            "captured",
        )
        self.assertEqual(
            result["evidence_exports"]["scan"]["status"],
            "captured",
        )
        self.assertFalse(
            result["evidence_quality"]["complete_evidence_verified"]
        )
        self.assertEqual(result["attack_attribution"], "unverified")

    def test_missing_scan_log_preserves_uncertainty(self):
        missing = self.root / "missing-scan.jsonl"
        meta = self.export_and_unpack("scan", missing)

        self.assertEqual(meta["status"], "unavailable")

        result = reporter.build_report(self.experiment)

        self.assertEqual(
            result["evidence_exports"]["scan"]["status"],
            "unavailable",
        )
        self.assertEqual(
            result["evidence_quality"]["status"],
            "unavailable",
        )
        self.assertFalse(
            result["evidence_quality"]["complete_evidence_verified"]
        )


if __name__ == "__main__":
    unittest.main()
