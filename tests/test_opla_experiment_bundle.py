import hashlib
import importlib.util
import json
import math
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

    @staticmethod
    def report_result(payload, returncode=0, stderr=""):
        return subprocess.CompletedProcess(
            args=[], returncode=returncode,
            stdout=json.dumps(payload), stderr=stderr
        )

    @staticmethod
    def valid_report():
        return {
            "schema_version": 1,
            "client_continuity": {
                "status": "unavailable",
                "covered_at_cadence": False,
                "continuous_availability_verified": False,
            },
            "evidence_quality": {"complete_evidence_verified": False},
        }

    def test_success_creates_manifest_report_and_metrics(self):
        fake_report = self.valid_report()
        result = self.report_result(fake_report)

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

    def test_injected_runner_receives_bounded_dispatch_contract(self):
        calls = []

        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            return self.report_result(self.valid_report())

        self.assertEqual(bundle.build(self.experiment, runner=runner, timeout=4.5), 0)
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(len(args), 1)
        self.assertEqual(kwargs, {
            "cwd": bundle.ROOT,
            "capture_output": True,
            "text": True,
            "check": False,
            "timeout": 4.5,
        })

    def test_invalid_timeout_is_rejected_before_dispatch(self):
        called = []

        def runner(*args, **kwargs):
            called.append(True)
            return self.report_result(self.valid_report())

        for timeout in (True, False, 0, -1, math.nan, math.inf, "30"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                bundle.build(self.experiment, runner=runner, timeout=timeout)
        self.assertEqual(called, [])

    def test_spawn_failure_is_durable_blocked_state_and_removes_stale_report(self):
        output = self.experiment / "pipeline"
        output.mkdir()
        (output / "incident-report.json").write_text("stale", encoding="utf-8")

        def runner(*args, **kwargs):
            raise OSError("runner unavailable")

        self.assertEqual(bundle.build(self.experiment, runner=runner), 1)
        manifest = json.loads((output / "manifest.json").read_text())
        metrics = json.loads((output / "monitoring-metrics.json").read_text())
        self.assertEqual(manifest["incident_report_status"], "blocked")
        self.assertIn("OSError", manifest["incident_report_error"])
        self.assertFalse((output / "incident-report.json").exists())
        self.assertEqual(metrics["metrics"]["opla.incident_report.generated"], 0)

    def test_timeout_is_durable_blocked_state(self):
        def runner(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        self.assertEqual(bundle.build(self.experiment, runner=runner, timeout=0.25), 1)
        manifest = json.loads(
            (self.experiment / "pipeline/manifest.json").read_text()
        )
        self.assertEqual(manifest["incident_report_status"], "blocked")
        self.assertIn("TimeoutExpired", manifest["incident_report_error"])

    def test_scalar_or_malformed_report_is_blocked(self):
        for payload in (None, [], "text", "{"):
            with self.subTest(payload=payload):
                if payload == "{":
                    result = subprocess.CompletedProcess([], 0, "{", "")
                else:
                    result = self.report_result(payload)
                self.assertEqual(bundle.build(self.experiment, runner=lambda *a, **k: result), 1)
                manifest = json.loads(
                    (self.experiment / "pipeline/manifest.json").read_text()
                )
                self.assertEqual(manifest["incident_report_status"], "blocked")
                self.assertFalse(
                    (self.experiment / "pipeline/incident-report.json").exists()
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
