import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import yaml  # noqa: F401
except ImportError:
    raise unittest.SkipTest("PyYAML unavailable; scenario YAML tests skipped")

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_scenario_live_fingerprint_test",
    ROOT / "bin/opla-scenario-live.py",
)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class LiveFingerprintTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        self.root = Path(tmp.name)
        self.folder = self.root / "reports" / "scenario-syn-TEST1234"
        self.folder.mkdir(parents=True)
        (self.folder / "before.json").write_text("{}")
        (self.folder / "after.json").write_text("{}")

        self.output = (
            "Материалы опыта: reports/scenario-syn-TEST1234\n"
        )

        patcher = patch.object(live, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_verified_fingerprint_accepted(self):
        with patch.object(
            live.evidence,
            "analyze_files",
            return_value={"telemetry_collected": True},
        ), patch.object(
            live.fp_evidence,
            "verify_directory",
            return_value={"status": "verified", "program_id": 42},
        ):
            result = live.read_scan_evidence(self.output)

        self.assertTrue(result["telemetry_collected"])
        self.assertEqual(result["fingerprint"]["status"], "verified")

    def test_unverified_fingerprint_rejected(self):
        with patch.object(
            live.evidence,
            "analyze_files",
            return_value={"telemetry_collected": True},
        ), patch.object(
            live.fp_evidence,
            "verify_directory",
            return_value={
                "status": "unverified",
                "reason": "fingerprints unavailable",
            },
        ):
            with self.assertRaisesRegex(
                RuntimeError, "fingerprint not verified"
            ):
                live.read_scan_evidence(self.output)

    def test_changed_program_rejected(self):
        with patch.object(
            live.evidence,
            "analyze_files",
            return_value={"telemetry_collected": True},
        ), patch.object(
            live.fp_evidence,
            "verify_directory",
            return_value={
                "status": "invalid",
                "reason": "program_id changed",
            },
        ):
            with self.assertRaisesRegex(
                RuntimeError, "program_id changed"
            ):
                live.read_scan_evidence(self.output)


if __name__ == "__main__":
    unittest.main()
