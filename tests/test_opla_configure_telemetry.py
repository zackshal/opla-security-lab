import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_configure_telemetry", ROOT / "bin/opla-configure-telemetry.py",
)
telemetry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(telemetry)


def healthy_snapshot():
    return {
        "loaded": 1,
        "mode": "native",
        "http_available": 1,
        "http_up": 1,
        "http_status": 200,
        "scan_enabled": 1,
        "scan_up": 1,
        "scan_details": "No port-scan event observed",
        "ids_enabled": 1,
        "ids_up": 1,
    }


class ConfigureTelemetryTests(unittest.TestCase):
    def test_all_required_sources_must_be_live(self):
        result = telemetry.validate_snapshot(healthy_snapshot())
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["xdp_mode"], "native")

    def test_each_missing_or_down_component_blocks_ready(self):
        for key in (
            "loaded", "http_available", "http_up", "http_status",
            "scan_enabled", "scan_up", "ids_enabled", "ids_up",
        ):
            snapshot = healthy_snapshot()
            snapshot[key] = 0
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, key):
                telemetry.validate_snapshot(snapshot)

    def test_unavailable_detector_and_unsupported_xdp_mode_block(self):
        snapshot = healthy_snapshot()
        snapshot["scan_details"] = "Detector unavailable or disabled"
        with self.assertRaisesRegex(ValueError, "scan detector"):
            telemetry.validate_snapshot(snapshot)
        snapshot = healthy_snapshot()
        snapshot["mode"] = "off"
        with self.assertRaisesRegex(ValueError, "XDP attachment"):
            telemetry.validate_snapshot(snapshot)

    def test_boolean_or_missing_metrics_are_not_accepted_as_integer_health(self):
        for key, value in (("ids_up", True), ("scan_up", None)):
            snapshot = healthy_snapshot()
            snapshot[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, key):
                telemetry.validate_snapshot(snapshot)

    def test_configuration_pipeline_checks_telemetry_before_reporting_pass(self):
        source = (ROOT / "bin/opla-lab-configure.sh").read_text()
        self.assertIn("make --no-print-directory xdp-stats", source)
        self.assertIn("bin/opla-configure-telemetry.py", source)
        self.assertLess(source.index("opla-configure-telemetry.py"),
                        source.index("PASS: OPLA laboratory components configured"))


if __name__ == "__main__":
    unittest.main()
