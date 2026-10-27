import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_scenario_live_evidence_test",
    ROOT / "bin/opla-scenario-live.py",
)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class LiveEvidenceTests(unittest.TestCase):

    def test_syn_scan_invokes_existing_traffic_script(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="Материалы опыта: reports/scenario-syn-ABCDEFGH\n",
            stderr="",
        )
        expected_evidence = {
            "telemetry_collected": True,
            "deltas": {"syn": 15, "drop": 0},
            "scan_detected": None,
        }

        with patch.object(live, "call", return_value=result) as call, \
             patch.object(
                 live,
                 "read_scan_evidence",
                 return_value=expected_evidence,
             ):
            item = live.run_stage(
                {"id": "scan", "kind": "syn-scan"},
                {},
                {},
            )

        self.assertEqual(call.call_args.args[0], [
            "bash", "bin/traffic-scenario.sh", "syn"
        ])
        self.assertEqual(item["status"], "completed")
        self.assertEqual(item["evidence"], expected_evidence)

    def test_missing_evidence_fails_stage(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="Generator finished, no snapshots",
            stderr="",
        )

        with patch.object(live, "call", return_value=result):
            item = live.run_stage(
                {"id": "scan", "kind": "syn-scan"},
                {},
                {},
            )

        self.assertEqual(item["status"], "failed")
        self.assertIn("evidence_error", item)

    def test_http_uses_client_and_checks_http_errors(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="HTTP=200\n",
            stderr="",
        )
        addresses = {
            "client": "192.0.2.3",
            "victim": "192.0.2.4",
        }

        with patch.object(live, "call", return_value=result) as call:
            item = live.run_stage(
                {"id": "availability", "kind": "http-probe"},
                {},
                addresses,
            )

        self.assertEqual(item["status"], "completed")
        command = call.call_args.args[0]
        self.assertEqual(command[:2], ["bash", "-c"])
        self.assertIn("--fail", command[2])
        self.assertIn("OPLA_CLIENT_IP", command[2])
        self.assertEqual(
            call.call_args.kwargs["env"]["OPLA_CLIENT_IP"],
            addresses["client"],
        )


if __name__ == "__main__":
    unittest.main()
