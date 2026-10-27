import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_event_correlator_test",
    ROOT / "bin/opla-event-correlator.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EventCorrelatorTests(unittest.TestCase):

    def test_multiple_sources(self):
        before = {
            "syn": 100,
            "drop": 10,
            "xdp_scan_events": 2,
            "scan_alerts": 5,
            "ids_alerts": 8,
        }
        after = {
            "syn": 200,
            "drop": 70,
            "xdp_scan_events": 3,
            "scan_alerts": 7,
            "ids_alerts": 10,
        }

        result = module.correlate(before, after)

        self.assertEqual(result["metrics"]["xdp"]["syn"], 100)
        self.assertEqual(result["metrics"]["xdp"]["drop"], 60)
        self.assertEqual(result["metrics"]["xdp"]["xdp_scan_events"], 1)
        self.assertEqual(result["metrics"]["scan_detector"]["scan_alerts"], 2)
        self.assertEqual(result["metrics"]["suricata"]["ids_alerts"], 2)
        self.assertEqual(result["attack_attribution"], "unverified")

    def test_missing_metrics_are_unknown(self):
        result = module.correlate({"syn": 0}, {"syn": 10})

        self.assertIsNone(
            result["observations"]["suricata_alerts"]
        )
        self.assertIsNone(
            result["observations"]["xdp_scan_events"]
        )

    def test_counter_reset_rejected(self):
        with self.assertRaises(ValueError):
            module.correlate(
                {"scan_alerts": 10},
                {"scan_alerts": 2},
            )

    def test_invalid_counter_rejected(self):
        with self.assertRaises(ValueError):
            module.correlate(
                {"ids_alerts": "10"},
                {"ids_alerts": 12},
            )


    def test_disabled_ids_is_unknown_not_false(self):
        before = {"ids_enabled": 0, "ids_up": 0, "ids_alerts": 0}
        after = dict(before)
        result = module.correlate(before, after)
        self.assertEqual(result["availability"]["suricata"], "unavailable")
        self.assertIsNone(result["observations"]["suricata_alerts"])

    def test_running_ids_with_no_alerts(self):
        before = {"ids_enabled": 1, "ids_up": 1, "ids_alerts": 10}
        after = dict(before)
        result = module.correlate(before, after)
        self.assertEqual(result["availability"]["suricata"], "available")
        self.assertFalse(result["observations"]["suricata_alerts"])

    def test_missing_detector_status_is_unknown(self):
        result = module.correlate(
            {"scan_alerts": 2}, {"scan_alerts": 2}
        )
        self.assertEqual(
            result["availability"]["scan_detector"], "unknown"
        )
        self.assertIsNone(
            result["observations"]["scan_detector_alerts"]
        )


if __name__ == "__main__":
    unittest.main()
