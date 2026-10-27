"""OPLA scenario execution adapter tests."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

engine = load_module("scenario_engine_test", ROOT / "bin/opla-scenario.py")
runner = load_module("scenario_runner_test", ROOT / "bin/opla-scenario-runner.py")


class ScenarioRunnerTests(unittest.TestCase):

    def setUp(self):
        data = yaml.safe_load(
            (ROOT / "scenarios/syn-scan-baseline.yaml").read_text()
        )
        self.plan = engine.validate(data)

    def test_execution_order(self):
        called = []

        def handler(stage):
            called.append(stage["id"])
            return {"dispatch_validated": True}

        report = runner.execute_plan(self.plan, handler)

        self.assertEqual(
            called,
            ["observe", "scan", "availability"],
        )
        self.assertEqual(report["status"], "simulation_completed")
        self.assertFalse(report["actual_execution"])

    def test_failure_stops_remaining_steps(self):
        called = []

        def handler(stage):
            called.append(stage["id"])
            if stage["id"] == "scan":
                raise RuntimeError("injected failure")
            return {}

        report = runner.execute_plan(self.plan, handler)

        self.assertEqual(called, ["observe", "scan"])
        self.assertEqual(report["status"], "simulation_failed")
        self.assertEqual(report["steps"][-1]["status"], "failed")

    def test_report_is_valid_json(self):
        report = runner.execute_plan(
            self.plan,
            runner.simulate_stage,
        )

        with tempfile.TemporaryDirectory() as temp:
            path = runner.save_report(report, Path(temp))
            saved = json.loads(path.read_text())

            self.assertEqual(saved["run_id"], report["run_id"])
            self.assertEqual(saved["mode"], "simulation")
            self.assertFalse(saved["telemetry_collected"])

    def test_unknown_action_blocked(self):
        self.plan["experiments"][0]["kind"] = "shell"

        with self.assertRaises(ValueError):
            runner.execute_plan(
                self.plan,
                runner.simulate_stage,
            )


if __name__ == "__main__":
    unittest.main()
