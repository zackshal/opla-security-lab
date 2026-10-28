"""Offline behavioral tests for custom OPLA infrastructure manifests."""

import copy
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:
    raise unittest.SkipTest("PyYAML unavailable; deployment YAML tests skipped")

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "opla-deploy.py"

spec = importlib.util.spec_from_file_location("opla_deploy_test", SCRIPT)
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
                "name": "web01",
                "address": "192.168.10.11",
                "ssh_user": "admin",
                "components": ["xdp", "telemetry-agent"],
                "interfaces": {"protection": "ens3"},
            },
            {
                "name": "ids01",
                "address": "192.168.20.12",
                "ssh_user": "admin",
                "components": ["suricata"],
                "interfaces": {"capture": "ens4"},
            },
        ],
    }


class DeployManifestTests(unittest.TestCase):

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

    def test_valid_custom_topology(self):
        data = self.validate(baseline())
        self.assertEqual(len(data["nodes"]), 2)

    def test_arbitrary_number_of_nodes(self):
        data = baseline()
        data["nodes"] = data["nodes"][:1]

        result = self.validate(data)
        self.assertEqual(len(result["nodes"]), 1)

    def test_duplicate_management_ip(self):
        data = baseline()
        data["nodes"][1]["address"] = "192.168.10.11"
        self.reject(data)

    def test_duplicate_node_name(self):
        data = baseline()
        data["nodes"][1]["name"] = "web01"
        self.reject(data)

    def test_invalid_ip_address(self):
        data = baseline()
        data["nodes"][0]["address"] = "999.999.1.1"
        self.reject(data)

    def test_invalid_ssh_port(self):
        data = baseline()
        data["nodes"][0]["ssh_port"] = 70000
        self.reject(data)

    def test_unknown_component(self):
        data = baseline()
        data["nodes"][0]["components"].append("unknown-service")
        self.reject(data)

    def test_xdp_requires_protection_interface(self):
        data = baseline()
        data["nodes"][0]["interfaces"] = {}
        self.reject(data)

    def test_suricata_requires_capture_interface(self):
        data = baseline()
        data["nodes"][1]["interfaces"] = {}
        self.reject(data)

    def test_valid_managed_vpn_declaration(self):
        data = baseline()
        data["connectivity"] = {
            "type": "managed_vpn",
            "engine": "amneziawg",
            "gateway": "vpn.example.org",
        }
        result = self.validate(data)
        self.assertEqual(
            result["connectivity"]["engine"], "amneziawg"
        )

    def test_invalid_vpn_engine(self):
        data = baseline()
        data["connectivity"] = {
            "type": "managed_vpn",
            "engine": "unsupported",
            "gateway": "vpn.example.org",
        }
        self.reject(data)

    def test_symlink_manifest_rejected(self):
        self.validate(baseline())
        link = Path(self.temp.name) / "linked.yaml"
        link.symlink_to(self.path)

        with self.assertRaises(ValueError):
            deploy.load_manifest(link)

    def test_duplicate_yaml_mapping_key_is_rejected(self):
        self.path.write_text(
            "apiVersion: opla/v1\napiVersion: ignored\nkind: Infrastructure\n",
            encoding="utf-8",
        )
        with self.assertRaises(yaml.YAMLError):
            deploy.load_manifest(self.path)

    def test_cli_plan_read_only(self):
        self.validate(baseline())

        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "bin" / "opla-cli.py"),
                "deploy",
                "plan",
                str(self.path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Nodes: 2", result.stdout)
        self.assertIn("No SSH connections attempted.", result.stdout)
        self.assertIn(
            "Deployment execution: NOT IMPLEMENTED",
            result.stdout,
        )


    def test_unknown_top_level_field(self):
        data = baseline()
        data["run_as_root"] = True
        self.reject(data)

    def test_unknown_metadata_field(self):
        data = baseline()
        data["metadata"]["provider"] = "cloud"
        self.reject(data)

    def test_unknown_node_field(self):
        data = baseline()
        data["nodes"][0]["ssh_idenity"] = "/tmp/key"
        self.reject(data)

    def test_valid_explicit_ssh_paths(self):
        data = baseline()
        data["nodes"][0]["ssh_identity"] = "~/.ssh/id_ed25519"
        data["nodes"][0]["ssh_known_hosts"] = (
            "~/.ssh/known_hosts"
        )
        self.validate(data)

    def test_reject_relative_ssh_identity(self):
        data = baseline()
        data["nodes"][0]["ssh_identity"] = "keys/id_ed25519"
        self.reject(data)

    def test_reject_ssh_path_traversal(self):
        data = baseline()
        data["nodes"][0]["ssh_identity"] = (
            "/home/student/../other/key"
        )
        self.reject(data)

    def test_valid_bastion_declaration(self):
        data = baseline()
        data["nodes"][0]["ssh_bastion"] = {
            "address": "192.0.2.20",
            "ssh_user": "admin",
            "ssh_port": 2222,
        }
        self.validate(data)

    def test_reject_unsafe_bastion(self):
        data = baseline()
        data["nodes"][0]["ssh_bastion"] = {
            "address": "not-an-ip",
            "ssh_user": "admin",
            "extra_ssh_options": "-o StrictHostKeyChecking=no",
        }
        self.reject(data)


if __name__ == "__main__":
    unittest.main()
