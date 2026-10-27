"""Real offline incident-to-bundle integration, without mocked reporter."""

import hashlib
import importlib.util
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipeline = load_module(
    "opla_existing_pipeline_tests",
    "tests/test_incident_pipeline.py",
)
bundle = load_module(
    "opla_bundle_e2e",
    "bin/opla-experiment-bundle.py",
)


class RealBundleE2ETests(unittest.TestCase):

    def setUp(self):
        # Reuse the existing complete offline experiment fixture.
        self.fixture = pipeline.IncidentPipelineTests(
            methodName="test_both_detectors_in_one_report"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.experiment = self.fixture.experiment

    def test_traffic_runner_uses_single_incident_report_pipeline(self):
        source = (ROOT / "bin/traffic-scenario.sh").read_text()

        self.assertIn(
            'python3 bin/opla-experiment-bundle.py "$output_dir"',
            source,
        )
        self.assertNotIn(
            'python3 bin/opla-incident-report.py',
            source,
        )

    def test_real_xdp_ids_correlation_reaches_bundle(self):
        eve_source = self.fixture.root / "source-eve.json"
        scan_source = self.fixture.root / "source-scan.jsonl"

        eve_source.write_text(
            json.dumps({
                "event_type": "alert",
                "timestamp": "2026-10-27T13:00:05Z",
                "src_ip": "100.64.0.2",
                "dest_ip": "100.64.0.3",
                "proto": "TCP",
                "dest_port": 80,
                "alert": {
                    "signature_id": 100001,
                    "signature": "Offline E2E test",
                    "action": "allowed",
                },
            }) + "\n",
            encoding="utf-8",
        )

        scan_source.write_text(
            json.dumps({
                "timestamp": int(datetime(
                    2026, 10, 27, 13, 0, 5,
                    tzinfo=timezone.utc
                ).timestamp()),
                "source_ip": "100.64.0.2",
                "destination_ip": "100.64.0.3",
                "event": "tcp_port_scan_suspected",
                "distinct_ports": 8,
                "sample_ports": list(range(20, 28)),
                "action": "alert",
            }) + "\n",
            encoding="utf-8",
        )

        self.fixture.export_and_unpack("suricata", eve_source)
        self.fixture.export_and_unpack("scan", scan_source)

        source_files = (
            "interval.json",
            "before.json",
            "after.json",
            "eve.json",
            "events.jsonl",
        )
        originals = {
            name: (self.experiment / name).read_bytes()
            for name in source_files
        }

        # IMPORTANT: no subprocess mocking.
        # Bundle invokes the real incident report CLI.
        rc = bundle.build(self.experiment)
        self.assertEqual(rc, 0)

        output = self.experiment / "pipeline"
        incident_path = output / "incident-report.json"

        incident = json.loads(incident_path.read_text())
        manifest = json.loads(
            (output / "manifest.json").read_text()
        )
        monitoring = json.loads(
            (output / "monitoring-metrics.json").read_text()
        )

        self.assertEqual(
            incident["counters"]["metrics"]["xdp"]["drop"], 40
        )
        self.assertEqual(
            incident["suricata"]["matching_alerts"], 1
        )
        self.assertEqual(
            incident["scan_detector"]["matching_events"], 1
        )

        self.assertEqual(
            incident["attack_attribution"], "unverified"
        )
        self.assertFalse(
            incident["evidence_quality"]["complete_evidence_verified"]
        )

        self.assertEqual(
            manifest["incident_report_status"], "generated"
        )
        self.assertEqual(
            manifest["incident_report_sha256"],
            hashlib.sha256(incident_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            monitoring["metrics"]["opla.incident_report.generated"], 1
        )
        self.assertEqual(
            monitoring["metrics"]["opla.evidence.suricata.present"], 1
        )
        self.assertEqual(
            monitoring["metrics"]["opla.evidence.scan.present"], 1
        )

        for name, original in originals.items():
            with self.subTest(source=name):
                self.assertEqual(
                    (self.experiment / name).read_bytes(),
                    original,
                )


if __name__ == "__main__":
    unittest.main()
