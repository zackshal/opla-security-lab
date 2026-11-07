"""OPLA scenario-engine validation contracts."""

import importlib.util
import unittest
from copy import deepcopy
from pathlib import Path

try:
    import yaml
except ImportError:
    raise unittest.SkipTest("PyYAML unavailable; scenario YAML tests skipped")


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/opla-scenario.py"

spec = importlib.util.spec_from_file_location("opla_scenario", SCRIPT)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class ScenarioEngineTests(unittest.TestCase):

    def setUp(self):
        self.data = yaml.safe_load(
            (ROOT / "scenarios/syn-scan-baseline.yaml").read_text()
        )

    def test_valid_scenario(self):
        plan = engine.validate(self.data)
        self.assertFalse(plan["execution_enabled"])
        self.assertEqual(plan["total_memory_mib"], 3584)
        self.assertEqual(len(plan["vms"]), 3)

    def test_rejects_unisolated_network(self):
        data = deepcopy(self.data)
        data["topology"]["network"] = "bridged"
        with self.assertRaises(ValueError):
            engine.validate(data)

    def test_rejects_unsupported_platform(self):
        data = deepcopy(self.data)
        data["platform"] = "windows-amd64"
        with self.assertRaises(ValueError):
            engine.validate(data)

    def test_rejects_resource_mismatch(self):
        data = deepcopy(self.data)
        data["topology"]["roles"]["victim"]["memory_mib"] = 4096
        with self.assertRaises(ValueError):
            engine.validate(data)

    def test_rejects_arbitrary_command(self):
        data = deepcopy(self.data)
        data["experiments"][0]["command"] = "echo bypass"
        with self.assertRaises(ValueError):
            engine.validate(data)

    def test_rejects_duplicate_step(self):
        data = deepcopy(self.data)
        data["experiments"][1]["id"] = "observe"
        with self.assertRaises(ValueError):
            engine.validate(data)

    def test_rejects_wrong_role(self):
        data = deepcopy(self.data)
        data["experiments"][1]["source"] = "client"
        with self.assertRaises(ValueError):
            engine.validate(data)

    def test_rejects_yaml_boolean_schema_version(self):
        data = deepcopy(self.data)
        data["schema_version"] = True
        with self.assertRaises(ValueError):
            engine.validate(data)


if __name__ == "__main__":
    unittest.main()
