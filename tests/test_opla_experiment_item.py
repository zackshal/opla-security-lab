import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


setup = load_module("opla_experiment_setup", "monitoring/setup.py")


class FakeAPI:
    def __init__(self):
        self.items = []

    def call(self, method, params):
        if method == "hostgroup.get":
            return [{"groupid": "1"}]
        if method == "host.get":
            return [{"hostid": "2"}]
        if method == "host.update":
            return {}
        if method == "item.get":
            return []
        if method == "item.create":
            self.items.append(params)
            return {"itemids": [str(len(self.items))]}
        if method == "trigger.get":
            return []
        if method == "trigger.create":
            return {"triggerids": ["1"]}
        if method == "graph.get":
            return []
        if method == "graph.create":
            return {"graphids": ["1"]}
        if method == "dashboard.get":
            return []
        if method == "dashboard.create":
            return {"dashboardids": ["1"]}
        raise AssertionError(f"Unexpected API call: {method}")


class ExperimentItemTests(unittest.TestCase):

    def test_experiment_event_is_registered_as_text_trapper(self):
        api = FakeAPI()

        setup.provision(api, "opla-lab-TEST")

        items = [
            item for item in api.items
            if item.get("key_") == "opla.experiment.event"
        ]

        self.assertEqual(len(items), 1)

        item = items[0]
        self.assertEqual(item["type"], 2)
        self.assertEqual(item["value_type"], 4)
        self.assertEqual(item["status"], 0)
        self.assertEqual(item["history"], "30d")
        self.assertEqual(item["trends"], "0")


if __name__ == "__main__":
    unittest.main()
