"""Offline tests for OPLA per-node connectivity planning."""

import copy
import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/opla-deploy.py"

spec = importlib.util.spec_from_file_location(
    "opla_connectivity_test", SCRIPT
)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def baseline():
    return {
        "apiVersion": "opla/v1",
        "kind": "Infrastructure",
        "metadata": {"name": "custom-network"},
        "connectivity": {"type": "direct"},
        "nodes": [
            {
                "name": "node01",
                "address": "10.100.0.11",
                "ssh_user": "admin",
                "components": ["xdp"],
                "interfaces": {"protection": "ens3"},
            }
        ],
    }


class ConnectivityTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "infra.yaml"

    def validate(self, data):
        self.path.write_text(
            yaml.safe_dump(data, sort_keys=False),
            encoding="utf-8",
        )
        return deploy.load_manifest(self.path)

    def reject(self, data):
        with self.assertRaises(ValueError):
            self.validate(data)

    def test_direct_ssh(self):
        data = self.validate(baseline())
        self.assertEqual(
            data["connectivity"]["type"], "direct"
        )

    def test_existing_vpn(self):
        data = baseline()
        data["connectivity"]["type"] = "existing_vpn"
        self.validate(data)

    def test_per_node_override(self):
        data = baseline()
        data["nodes"][0]["connectivity"] = {
            "type": "existing_vpn"
        }

        validated = self.validate(data)

        output = io.StringIO()
        with redirect_stdout(output):
            deploy.show_connectivity_plan(validated)

        self.assertIn("Transport: existing_vpn", output.getvalue())

    def test_amneziawg(self):
        data = baseline()
        data["nodes"][0]["connectivity"] = {
            "type": "managed_vpn",
            "engine": "amneziawg",
            "gateway": "vpn.example.org",
        }
        self.validate(data)

    def test_xray(self):
        data = baseline()
        data["nodes"][0]["connectivity"] = {
            "type": "managed_vpn",
            "engine": "xray",
            "gateway": "vpn.example.org",
        }
        validated = self.validate(data)
        self.assertEqual(
            validated["nodes"][0]["connectivity"]["engine"],
            "xray",
        )

    def test_unknown_connectivity_field_rejected(self):
        data = baseline()
        data["nodes"][0]["connectivity"] = {
            "type": "direct",
            "execute": True,
        }
        self.reject(data)

    def test_vpn_fields_rejected_for_direct_ssh(self):
        data = baseline()
        data["connectivity"]["gateway"] = "vpn.example.org"
        self.reject(data)

    def test_missing_managed_gateway_rejected(self):
        data = baseline()
        data["connectivity"] = {
            "type": "managed_vpn",
            "engine": "amneziawg",
        }
        self.reject(data)

    def test_plan_does_not_execute_network_commands(self):
        data = self.validate(baseline())
        output = io.StringIO()

        with patch.object(
            deploy, "show_plan", side_effect=AssertionError(
                "unexpected deployment planner"
            )
        ), patch(
            "subprocess.run",
            side_effect=AssertionError("subprocess called"),
        ), patch(
            "socket.create_connection",
            side_effect=AssertionError("network called"),
        ), redirect_stdout(output):
            deploy.show_connectivity_plan(data)

        self.assertIn(
            "No SSH/VPN connections attempted.",
            output.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
