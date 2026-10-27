import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/opla-experiment-bundle.py"

spec = importlib.util.spec_from_file_location("opla_bundle_test", SCRIPT)
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class ExperimentBundleTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.experiment = Path(self.temp.name) / "scenario-test-001"
        self.experiment.mkdir()

        (self.experiment / "before.json").write_text(
            '{"syn": 10}', encoding="utf-8"
        )
        (self.experiment / "after.json").write_text(
            '{"syn": 20}', encoding="utf-8"
        )

    def test_success_creates_manifest_report_and_metrics(self):
        fake_report = {
            "schema_version": 1,
            "evidence_quality": {
                "complete_evidence_verified": False
            },
        }
        result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=json.dumps(fake_report), stderr=""
        )

        with patch.object(bundle.subprocess, "run", return_value=result):
            rc = bundle.build(self.experiment)

        self.assertEqual(rc, 0)
        output = self.experiment / "pipeline"

        incident = json.loads(
            (output / "incident-report.json").read_text()
        )
        manifest = json.loads(
            (output / "manifest.json").read_text()
        )
        metrics = json.loads(
            (output / "monitoring-metrics.json").read_text()
        )

        self.assertEqual(incident, fake_report)
        self.assertEqual(
            manifest["incident_report_status"], "generated"
        )
        self.assertFalse(
            manifest["evidence_quality"]["complete_evidence_verified"]
        )
        self.assertEqual(
            metrics["metrics"]["opla.incident_report.generated"], 1
        )
        self.assertEqual(
            metrics["metrics"]["opla.evidence.suricata.present"], 0
        )
        self.assertEqual(
            manifest["incident_report_sha256"],
            hashlib.sha256(
                (output / "incident-report.json").read_bytes()
            ).hexdigest(),
        )

    def test_failed_report_is_marked_blocked(self):
        result = subprocess.CompletedProcess(
            args=[], returncode=2,
            stdout="", stderr="BLOCKED: missing interval.json"
        )

        with patch.object(bundle.subprocess, "run", return_value=result):
            rc = bundle.build(self.experiment)

        self.assertEqual(rc, 1)
        output = self.experiment / "pipeline"
        manifest = json.loads(
            (output / "manifest.json").read_text()
        )
        metrics = json.loads(
            (output / "monitoring-metrics.json").read_text()
        )

        self.assertEqual(
            manifest["incident_report_status"], "blocked"
        )
        self.assertIn(
            "missing interval.json",
            manifest["incident_report_error"]
        )
        self.assertFalse((output / "incident-report.json").exists())
        self.assertEqual(
            metrics["metrics"]["opla.incident_report.generated"], 0
        )

    def test_source_evidence_is_not_modified(self):
        source = self.experiment / "before.json"
        original = source.read_bytes()

        result = subprocess.CompletedProcess(
            args=[], returncode=2,
            stdout="", stderr="BLOCKED"
        )

        with patch.object(bundle.subprocess, "run", return_value=result):
            bundle.build(self.experiment)

        self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
