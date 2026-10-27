import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "monitoring/experiment-publish.py"

spec = importlib.util.spec_from_file_location("opla_publisher_test", SCRIPT)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


class ExperimentPublishTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)

        self.experiment = Path(temp.name) / "scenario-syn-OFFLINE"
        self.pipeline = self.experiment / "pipeline"
        self.pipeline.mkdir(parents=True)

        self.report = {
            "schema_version": 1,
            "evidence_quality": {
                "status": "partial_or_unverified",
                "complete_evidence_verified": False,
            },
            "attack_attribution": "unverified",
        }

        self.report_path = self.pipeline / "incident-report.json"
        write_json(self.report_path, self.report)

        self.manifest = {
            "schema_version": 1,
            "experiment": self.experiment.name,
            "incident_report_status": "generated",
            "incident_report_error": None,
            "evidence_quality": self.report["evidence_quality"],
            "incident_report_sha256": hashlib.sha256(
                self.report_path.read_bytes()
            ).hexdigest(),
            "created_at": "2026-10-27T15:00:00+00:00",
        }

        self.metrics = {
            "schema_version": 1,
            "experiment": self.experiment.name,
            "metrics": {
                "opla.incident_report.generated": 1,
                "opla.evidence.suricata.present": 1,
                "opla.evidence.scan.present": 1,
            },
        }

        write_json(self.pipeline / "manifest.json", self.manifest)
        write_json(self.pipeline / "monitoring-metrics.json", self.metrics)

    def test_generated_event_contains_identity_and_quality(self):
        record = publisher.prepare(self.experiment, "lab-OFFLINE")
        event = json.loads(record["value"])

        self.assertEqual(record["host"], "opla-lab-OFFLINE")
        self.assertEqual(record["key"], "opla.experiment.event")
        self.assertEqual(event["experiment"], self.experiment.name)
        self.assertEqual(event["report_status"], "generated")
        self.assertEqual(event["attack_attribution"], "unverified"
                         ) if "attack_attribution" in event else self.assertEqual(
                             event["evidence_quality"],
                             self.report["evidence_quality"],
                         )
        self.assertEqual(
            event["incident_report_sha256"],
            self.manifest["incident_report_sha256"],
        )

    def test_tampered_report_is_rejected(self):
        self.report_path.write_text('{"modified":true}', encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "SHA-256"):
            publisher.prepare(self.experiment, "lab-OFFLINE")

    def test_wrong_experiment_id_is_rejected(self):
        self.manifest["experiment"] = "scenario-syn-OTHER"
        write_json(self.pipeline / "manifest.json", self.manifest)

        with self.assertRaisesRegex(ValueError, "mismatch"):
            publisher.prepare(self.experiment, "lab-OFFLINE")

    def test_blocked_report_can_be_published_as_blocked(self):
        self.report_path.unlink()
        self.manifest["incident_report_status"] = "blocked"
        self.manifest["incident_report_error"] = "missing interval.json"
        self.manifest.pop("incident_report_sha256")
        self.metrics["metrics"]["opla.incident_report.generated"] = 0
        write_json(self.pipeline / "manifest.json", self.manifest)
        write_json(self.pipeline / "monitoring-metrics.json", self.metrics)

        record = publisher.prepare(self.experiment, "lab-OFFLINE")
        event = json.loads(record["value"])

        self.assertEqual(event["report_status"], "blocked")
        self.assertIsNone(event["incident_report_sha256"])
        self.assertEqual(event["metrics"]["opla.incident_report.generated"], 0)

    def test_dry_run_never_calls_network_sender(self):
        args = [
            "experiment-publish.py",
            "--lab", "lab-OFFLINE",
            "--experiment", str(self.experiment),
            "--dry-run",
        ]
        with patch.object(sys, "argv", args), patch.object(
            publisher, "send"
        ) as sender:
            self.assertEqual(publisher.main(), 0)
            sender.assert_not_called()


if __name__ == "__main__":
    unittest.main()
