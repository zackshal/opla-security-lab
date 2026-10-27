import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "bin/opla-connectivity-check.py"

spec = importlib.util.spec_from_file_location(
    "opla_connectivity_check_test", path
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

NODE = {
    "name": "node01",
    "address": "192.0.2.10",
    "ssh_user": "admin",
    "ssh_port": 2222,
    "components": ["xdp"],
    "interfaces": {"protection": "ens3"},
}
DEFAULT = {"type": "direct"}


class ConnectivityCheckTests(unittest.TestCase):

    def test_managed_vpn_not_provisioned(self):
        status, _ = module.check_node(
            NODE, {"type": "managed_vpn"}, False
        )
        self.assertEqual(status, "NOT TESTED")

    @patch.object(module, "known_host", return_value=False)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    def test_missing_host_key_blocks(self, *_):
        status, message = module.check_node(NODE, DEFAULT, False)
        self.assertEqual(status, "BLOCKED")
        self.assertIn("not pinned", message)

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module.subprocess, "run")
    def test_offline_never_connects(self, run, *_):
        status, _ = module.check_node(NODE, DEFAULT, False)
        self.assertEqual(status, "NOT TESTED")
        run.assert_not_called()

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module.subprocess, "run")
    def test_explicit_connect_has_strict_ssh(self, run, *_):
        run.return_value = subprocess.CompletedProcess(
            [], 0, "", ""
        )

        status, _ = module.check_node(NODE, DEFAULT, True)
        self.assertEqual(status, "PASS")

        command = run.call_args.args[0]
        self.assertEqual(command[0], "ssh")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=yes", command)
        self.assertIn("2222", command)
        self.assertIn("admin@192.0.2.10", command)
        self.assertEqual(command[-1], "true")

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module.subprocess, "run")
    def test_ssh_error_blocks(self, run, *_):
        run.return_value = subprocess.CompletedProcess(
            [], 255, "", "failure"
        )
        status, _ = module.check_node(NODE, DEFAULT, True)
        self.assertEqual(status, "BLOCKED")

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module.subprocess, "run")
    def test_bastion_connect_fails_closed(self, run, *_):
        node = dict(NODE)
        node["ssh_bastion"] = {
            "address": "192.0.2.20",
            "ssh_user": "admin",
        }
        status, reason = module.check_node(node, DEFAULT, True)
        self.assertEqual(status, "BLOCKED")
        self.assertIn("bastion", reason)
        run.assert_not_called()

    def test_invalid_bastion_rejected(self):
        with self.assertRaises(ValueError):
            module.validate_bastion({
                "address": "not-an-ip",
                "ssh_user": "admin",
            })


if __name__ == "__main__":
    unittest.main()
