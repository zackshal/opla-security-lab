"""Bounded independent-client evidence; synthetic artifacts, no live collection."""

import asyncio
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

try:
    from tests import test_lifecycle_artifacts as fixtures
except (ImportError, unittest.SkipTest):
    fixtures = None

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("client_coverage_report", ROOT / "bin/opla-incident-report.py")
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)
bundle_spec = importlib.util.spec_from_file_location("client_coverage_bundle", ROOT / "bin/opla-experiment-bundle.py")
bundle = importlib.util.module_from_spec(bundle_spec)
bundle_spec.loader.exec_module(bundle)


def context():
    return {
        "schema_version": 1, "lab_id": "lab-offline123", "experiment": "scenario-syn-OFFLINE",
        "clock_source": "victim", "client_ip": "100.64.0.4", "source_ip": "100.64.0.2",
        "target_ip": "100.64.0.3", "start": "2026-10-27T13:00:00Z",
        "end": "2026-10-27T13:00:10Z",
    }


def series():
    return {
        "schema_version": 1, "lab_id": "lab-offline123", "experiment": "scenario-syn-OFFLINE",
        "clock_source": "victim", "source_role": "client", "target_role": "victim",
        "source_ip": "100.64.0.4", "target_ip": "100.64.0.3",
        "samples": [{"timestamp": f"2026-10-27T13:00:{second:02d}Z", "returncode": 0,
                     "http_status": 200} for second in range(0, 11, 2)],
    }


def analyze(interval=None, probes=None, gap=2):
    return reporter.counters.client_continuity(
        context() if interval is None else interval, series() if probes is None else probes,
        parse_time=reporter.eve.parse_time, max_gap_seconds=gap)


class ClientSeriesTests(unittest.TestCase):
    def test_valid_samples_prove_only_bounded_coverage(self):
        result = analyze()
        self.assertEqual(result["status"], "covered_at_cadence")
        self.assertEqual(result["sample_count"], 6)
        self.assertEqual(result["observed_maximum_gap_seconds"], 2)
        self.assertFalse(result["continuous_availability_verified"])
        self.assertEqual(result["provenance"], "unverified")

    def test_exact_threshold_is_accepted_but_just_over_is_not(self):
        self.assertTrue(analyze(gap=2)["covered_at_cadence"])
        self.assertFalse(analyze(gap=1.999999)["covered_at_cadence"])

    def test_caller_gap_rejects_invalid_numbers(self):
        for gap in (True, False, 0, -1, math.nan, math.inf, "2"):
            with self.subTest(gap=gap), self.assertRaises(ValueError):
                analyze(gap=gap)

    def test_artifact_cannot_relax_sampling_gap(self):
        probes = series()
        probes["samples"] = [probes["samples"][index] for index in (0, 1, 4, 5)]
        probes["max_gap_seconds"] = 9999
        self.assertFalse(analyze(probes=probes)["covered_at_cadence"])

    def test_one_point_cannot_cover_interval(self):
        probes = series()
        probes["samples"] = probes["samples"][:1]
        with self.assertRaises(ValueError):
            analyze(probes=probes)

    def test_missing_leading_or_trailing_boundary_fails(self):
        for selected in (slice(1, None), slice(None, -1)):
            with self.subTest(selected=selected):
                probes = series()
                probes["samples"] = probes["samples"][selected]
                self.assertFalse(analyze(probes=probes)["covered_at_cadence"])

    def test_just_outside_samples_cannot_replace_in_interval_evidence(self):
        probes = series()
        probes["samples"] = [dict(probes["samples"][0], timestamp="2026-10-27T12:59:59Z"),
                             dict(probes["samples"][-1], timestamp="2026-10-27T13:00:11Z")]
        result = analyze(probes=probes, gap=20)
        self.assertFalse(result["covered_at_cadence"])
        self.assertIn("insufficient_samples_within_interval", result["reasons"])

    def test_failed_probe_is_not_coverage(self):
        for field, value in (("returncode", 28), ("http_status", 503)):
            with self.subTest(field=field):
                probes = series()
                probes["samples"][2][field] = value
                result = analyze(probes=probes)
                self.assertFalse(result["covered_at_cadence"])
                self.assertEqual(result["unsuccessful_samples"], 1)

    def test_boolean_status_or_return_code_is_malformed(self):
        for field in ("returncode", "http_status"):
            with self.subTest(field=field):
                probes = series()
                probes["samples"][0][field] = True
                with self.assertRaises(ValueError):
                    analyze(probes=probes)

    def test_wrong_envelope_identity_or_clock_fails(self):
        for field, value in (("lab_id", "lab-other123"), ("experiment", "scenario-syn-OTHER"),
                             ("clock_source", "client"), ("source_role", "victim"),
                             ("target_role", "client"), ("source_ip", "100.64.0.2"),
                             ("target_ip", "100.64.0.99")):
            with self.subTest(field=field):
                probes = series()
                probes[field] = value
                with self.assertRaises(ValueError):
                    analyze(probes=probes)

    def test_client_cannot_be_victim_or_attacker_even_when_claims_match(self):
        for address in ("100.64.0.2", "100.64.0.3"):
            with self.subTest(address=address):
                interval, probes = context(), series()
                interval["client_ip"] = probes["source_ip"] = address
                with self.assertRaises(ValueError):
                    analyze(interval, probes)

    def test_missing_expected_client_is_not_taken_from_probe(self):
        interval = context()
        del interval["client_ip"]
        with self.assertRaises((KeyError, ValueError)):
            analyze(interval)

    def test_unsupported_or_boolean_schema_fails(self):
        for value in (True, 2):
            with self.subTest(schema=value):
                probes = series()
                probes["schema_version"] = value
                with self.assertRaises(ValueError):
                    analyze(probes=probes)

    def test_duplicate_or_out_of_order_times_fail(self):
        for second in ("2026-10-27T13:00:00Z", "2026-10-27T12:59:59Z"):
            with self.subTest(second=second):
                probes = series()
                probes["samples"][1]["timestamp"] = second
                with self.assertRaises(ValueError):
                    analyze(probes=probes)

    def test_non_string_and_naive_timestamps_fail(self):
        for value in (True, math.nan, math.inf, 0, None, "2026-10-27T13:00:00"):
            with self.subTest(timestamp=value):
                probes = series()
                probes["samples"][0]["timestamp"] = value
                with self.assertRaises(ValueError):
                    analyze(probes=probes)

    def test_nonpositive_or_naive_interval_fails(self):
        for start, end in ((context()["end"], context()["start"]),
                           (context()["start"], context()["start"]),
                           ("2026-10-27T13:00:00", context()["end"])):
            with self.subTest(start=start, end=end):
                interval = dict(context(), start=start, end=end)
                with self.assertRaises(ValueError):
                    analyze(interval)

    def test_record_limit_is_checked_before_analysis(self):
        probes = series()
        probes["samples"] = probes["samples"] * (reporter.counters.MAX_CLIENT_SAMPLES + 1)
        with self.assertRaises(ValueError):
            analyze(probes=probes)


class ClientArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.experiment = Path(self.tmp.name) / context()["experiment"]
        self.experiment.mkdir()
        self.path = self.experiment / "client-probes.json"

    def write(self, data=None):
        self.path.write_text(json.dumps(series() if data is None else data))

    def coverage(self, interval=None):
        return reporter.client_continuity_report(self.experiment, context() if interval is None else interval)

    def test_missing_is_unavailable(self):
        self.assertEqual(self.coverage()["status"], "unavailable")

    def test_hash_is_of_the_same_bounded_bytes_parsed(self):
        self.write()
        result = self.coverage()
        self.assertTrue(result["covered_at_cadence"])
        self.assertEqual(result["artifact_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_corrupt_json_is_invalid_not_covered(self):
        self.path.write_bytes(b"{")
        result = self.coverage()
        self.assertEqual(result["status"], "invalid")
        self.assertFalse(result["covered_at_cadence"])

    def test_oversized_artifact_is_rejected_before_json(self):
        self.path.write_bytes(b" " * (reporter.MAX_CLIENT_EVIDENCE_BYTES + 1))
        self.assertEqual(self.coverage()["status"], "invalid")

    def test_symlink_or_hardlink_artifact_is_rejected(self):
        other = self.experiment / "original.json"
        other.write_text(json.dumps(series()))
        self.path.symlink_to(other)
        self.assertEqual(self.coverage()["status"], "invalid")
        self.path.unlink()
        os.link(other, self.path)
        self.assertEqual(self.coverage()["status"], "invalid")

    def test_fifo_artifact_is_rejected_without_blocking(self):
        os.mkfifo(self.path)
        self.assertEqual(self.coverage()["status"], "invalid")

    def test_report_readers_reject_hardlinks(self):
        interval = self.experiment / "interval.json"
        external_interval = Path(self.tmp.name) / "interval-original.json"
        external_interval.write_text(json.dumps(context()))
        interval.hardlink_to(external_interval)
        with self.assertRaises(ValueError):
            reporter.read_json(interval)

        events = self.experiment / "events.jsonl"
        external_events = Path(self.tmp.name) / "events-original.jsonl"
        external_events.write_text(json.dumps({"timestamp": 1793106005}) + "\n")
        events.hardlink_to(external_events)
        with self.assertRaises(ValueError):
            reporter.scan_events(events, context()["start"], context()["end"],
                                 context()["source_ip"], context()["target_ip"])

    def test_directory_experiment_binding_is_required(self):
        self.write()
        interval = dict(context(), experiment="scenario-syn-OTHER")
        self.assertEqual(self.coverage(interval)["status"], "invalid")


@unittest.skipIf(fixtures is None, "PyYAML unavailable; lifecycle integration tests skipped")
class ClientIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ArtifactAcceptanceTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.write("interval.json", context())

    def write(self, probes=None):
        self.fixture.write("client-probes.json", series() if probes is None else probes)

    def strict(self):
        old = self.fixture.adapter
        self.fixture.adapter = fixtures.artifacts.ArtifactAdapter(
            self.fixture.operations, image_directory=old.image_directory,
            image_runner=old.image_runner, scenario=old.scenario, experiment=old.experiment,
            strict_client_coverage=True)

    def test_reporter_and_bundle_preserve_global_uncertainty(self):
        self.write()
        report = reporter.build_report(self.fixture.experiment)
        self.assertTrue(report["client_continuity"]["covered_at_cadence"])
        self.assertFalse(report["evidence_quality"]["complete_evidence_verified"])
        self.assertEqual(bundle.build(self.fixture.experiment), 0)
        manifest = json.loads((self.fixture.experiment / "pipeline/manifest.json").read_text())
        hashed = manifest["evidence"]["client-probes.json"]
        self.assertEqual(hashed["status"], "present")
        self.assertEqual(hashed["sha256"], report["client_continuity"]["artifact_sha256"])
        self.assertFalse(manifest["evidence_quality"]["complete_evidence_verified"])

    def test_bundle_blocks_when_client_bytes_change_after_inventory(self):
        self.write()
        original_run = bundle.subprocess.run

        def rewrite_before_report(*args, **kwargs):
            with (self.fixture.experiment / "client-probes.json").open("ab") as stream:
                stream.write(b"\n")
            return original_run(*args, **kwargs)

        with mock.patch.object(bundle.subprocess, "run", side_effect=rewrite_before_report):
            self.assertEqual(bundle.build(self.fixture.experiment), 1)

        output = self.fixture.experiment / "pipeline"
        manifest = json.loads((output / "manifest.json").read_text())
        metrics = json.loads((output / "monitoring-metrics.json").read_text())
        self.assertEqual(manifest["incident_report_status"], "blocked")
        self.assertIn("changed after inventory", manifest["incident_report_error"])
        self.assertNotIn("incident_report_sha256", manifest)
        self.assertFalse((output / "incident-report.json").exists())
        self.assertEqual(metrics["metrics"]["opla.incident_report.generated"], 0)

    def test_bundle_blocks_when_report_input_changes_after_inventory(self):
        self.write()
        original_run = bundle.subprocess.run

        def rewrite_eve_before_report(*args, **kwargs):
            eve_path = self.fixture.experiment / "eve.json"
            event = json.loads(eve_path.read_text())
            event["alert"]["signature"] = "fixture-mutated"
            eve_path.write_text(json.dumps(event) + "\n")
            return original_run(*args, **kwargs)

        with mock.patch.object(bundle.subprocess, "run", side_effect=rewrite_eve_before_report):
            self.assertEqual(bundle.build(self.fixture.experiment), 1)

        output = self.fixture.experiment / "pipeline"
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["incident_report_status"], "blocked")
        self.assertIn("report input changed after inventory: eve.json",
                      manifest["incident_report_error"])
        self.assertFalse((output / "incident-report.json").exists())

    def test_bundle_blocks_when_client_artifact_appears_after_inventory(self):
        original_run = bundle.subprocess.run

        def create_before_report(*args, **kwargs):
            self.write()
            return original_run(*args, **kwargs)

        with mock.patch.object(bundle.subprocess, "run", side_effect=create_before_report):
            self.assertEqual(bundle.build(self.fixture.experiment), 1)

        output = self.fixture.experiment / "pipeline"
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["evidence"]["client-probes.json"]["status"], "missing")
        self.assertEqual(manifest["incident_report_status"], "blocked")
        self.assertFalse((output / "incident-report.json").exists())

    def test_legacy_missing_artifact_is_explicitly_unavailable(self):
        report = reporter.build_report(self.fixture.experiment)
        self.assertEqual(report["client_continuity"]["status"], "unavailable")
        result = self.fixture.run_lab()
        self.assertEqual(result["steps"]["scenario"]["status"], "PASS")

    def test_strict_missing_artifact_cannot_use_optimistic_point_probe(self):
        self.strict()
        result = self.fixture.run_lab()
        self.assertEqual(result["steps"]["scenario"]["status"], "FAILED")
        self.assertNotIn("telemetry", self.fixture.operations.actions)

    def test_strict_coverage_is_integrated_and_hashed(self):
        self.write()
        self.strict()
        result = self.fixture.run_lab()
        self.assertEqual(result["steps"]["scenario"]["status"], "PASS")
        self.assertEqual(result["steps"]["telemetry"]["status"], "PASS")
        self.assertEqual(result["steps"]["report"]["status"], "FAILED")
        evidence = result["steps"]["telemetry"]["evidence"]["probe"]
        self.assertTrue(evidence["client_continuity"]["covered_at_cadence"])
        self.assertEqual(evidence["artifact_sha256"]["client-probes.json"],
                         evidence["client_continuity"]["artifact_sha256"])

    def test_invalid_or_missing_coverage_is_reparsed_before_resume_actions(self):
        self.write()
        self.strict()
        self.fixture.run_lab()
        self.fixture.operations.actions.clear()
        (self.fixture.experiment / "client-probes.json").unlink()
        result = self.fixture.run_lab(resume=True)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(self.fixture.operations.actions, [])

    def test_other_lab_artifacts_cannot_satisfy_strict_request(self):
        self.write(dict(series(), lab_id="lab-other123"))
        self.fixture.write("interval.json", dict(context(), lab_id="lab-other123"))
        self.strict()
        self.assertEqual(self.fixture.run_lab()["steps"]["scenario"]["status"], "FAILED")

    def test_strict_gap_configuration_is_validated(self):
        old = self.fixture.adapter
        for gap in (True, 0, -1, math.inf, math.nan):
            with self.subTest(gap=gap), self.assertRaises(ValueError):
                fixtures.artifacts.ArtifactAdapter(
                    self.fixture.operations, image_directory=old.image_directory,
                    image_runner=old.image_runner, scenario=old.scenario, experiment=old.experiment,
                    strict_client_coverage=True, max_client_gap_seconds=gap)


if __name__ == "__main__":
    unittest.main()
