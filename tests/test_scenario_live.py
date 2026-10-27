"""Safety contracts for OPLA live scenario adapter."""

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/opla-scenario-live.py"

spec = importlib.util.spec_from_file_location("opla_scenario_live", SCRIPT)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class LiveScenarioTests(unittest.TestCase):

    def test_invalid_lab_identifier(self):
        for value in ("../other", "lab-x/../y", "", "lab-;id"):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    live.validate_lab(value)

    def test_unknown_action_rejected(self):
        with self.assertRaises(RuntimeError):
            live.run_stage(
                {"id": "bad", "kind": "arbitrary-shell"},
                {},
                {},
            )

    def test_non_root_executor_rejected(self):
        with patch.object(live.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                live.executor_authorized()

    def test_missing_executor_authorization_rejected(self):
        with patch.object(live.os, "geteuid", return_value=0), \
             patch.object(
                 live,
                 "AUTH_FILE",
                 Path("/nonexistent/opla-executor-authorized"),
             ):
            with self.assertRaises(RuntimeError):
                live.executor_authorized()


if __name__ == "__main__":
    unittest.main()
