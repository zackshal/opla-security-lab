import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "bin/opla-lab-orchestrator.py"
)

spec = importlib.util.spec_from_file_location(
    "opla_lab_orchestrator_test",
    SCRIPT,
)

module = importlib.util.module_from_spec(spec)

import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class OrchestratorTests(unittest.TestCase):

    def test_all_steps_success(self):
        results = module.run_steps(
            lambda _: True
        )
        self.assertEqual(
            set(results.values()),
            {"PASS"},
        )

    def test_failure_stops_downstream(self):
        called = []

        def execute(step):
            called.append(step)
            return step != "create"

        result = module.run_steps(execute)

        self.assertEqual(
            called,
            ["preflight", "create"],
        )
        self.assertEqual(
            result["configure"],
            "NOT RUN",
        )
        self.assertEqual(
            result["health"],
            "NOT RUN",
        )

    def test_exception_fails_closed(self):
        def execute(_):
            raise RuntimeError("failure")

        result = module.run_steps(execute)

        self.assertEqual(
            result["preflight"],
            "FAILED",
        )
        self.assertEqual(
            result["create"],
            "NOT RUN",
        )

    def test_journal_callback(self):
        recorded = []

        module.run_steps(
            lambda _: True,
            recorded.append,
        )

        self.assertEqual(
            recorded[0]["health"],
            "PASS",
        )

    def test_missing_contract_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                module.validate_contract(tmp)

    def test_invalid_lab_rejected(self):
        with self.assertRaises(SystemExit):
            module.main(
                ["plan", "--lab", "../escape"]
            )


if __name__ == "__main__":
    unittest.main()
