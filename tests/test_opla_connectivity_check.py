import importlib.util
import subprocess
import tempfile
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
    @patch.object(module, "run_bounded")
    def test_offline_never_connects(self, run, *_):
        status, _ = module.check_node(NODE, DEFAULT, False)
        self.assertEqual(status, "NOT TESTED")
        run.assert_not_called()

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh")
    @patch.object(module, "run_bounded")
    def test_explicit_connect_has_strict_ssh(self, run, *_):
        run.return_value = subprocess.CompletedProcess(
            [], 0, "", ""
        )

        status, _ = module.check_node(NODE, DEFAULT, True)
        self.assertEqual(status, "PASS")

        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/ssh")
        expected_options = (
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=/tmp/known_hosts",
            "GlobalKnownHostsFile=/dev/null",
            "UpdateHostKeys=no",
            "ConnectTimeout=5",
            "ConnectionAttempts=1",
            "ControlMaster=no",
            "ClearAllForwardings=yes",
            "PreferredAuthentications=publickey",
        )
        for option in expected_options:
            self.assertIn(option, command)
        self.assertIn("-F", command)
        self.assertIn("/dev/null", command)
        self.assertEqual(run.call_args.kwargs["timeout"], 20)
        self.assertEqual(run.call_args.kwargs["max_output_bytes"], module.MAX_COMMAND_OUTPUT_BYTES)
        self.assertIn("2222", command)
        self.assertIn("admin@192.0.2.10", command)
        self.assertEqual(command[-1], "true")
        self.assertNotIn("-A", command)

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", side_effect=lambda value, label, private=False: value)
    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh")
    @patch.object(module, "run_bounded")
    def test_explicit_identity_is_exact_and_agent_restricted(self, run, *_):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        node = dict(NODE, ssh_identity="/home/test/.ssh/lab_key")
        status, _ = module.check_node(node, DEFAULT, True)
        self.assertEqual(status, "PASS")
        command = run.call_args.args[0]
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertIn("/home/test/.ssh/lab_key", command)

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh")
    @patch.object(module, "run_bounded", side_effect=subprocess.TimeoutExpired("ssh", 20))
    def test_ssh_timeout_blocks(self, run, *_):
        status, _ = module.check_node(NODE, DEFAULT, True)
        self.assertEqual(status, "BLOCKED")
        run.assert_called_once()

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh")
    @patch.object(module, "run_bounded")
    def test_ssh_output_limit_blocks(self, run, *_):
        result = subprocess.CompletedProcess([], 1, "x" * module.MAX_COMMAND_OUTPUT_BYTES, "")
        result.output_limited = True
        run.return_value = result
        status, message = module.check_node(NODE, DEFAULT, True)
        self.assertEqual(status, "BLOCKED")
        self.assertIn("output", message)

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh")
    @patch.object(module, "run_bounded")
    def test_ssh_output_limit_cleanup_uncertainty_is_reported(self, run, *_):
        result = subprocess.CompletedProcess([], 1, "", "")
        result.output_limited = True
        result.cleanup_error = "process group remains"
        run.return_value = result
        status, message = module.check_node(NODE, DEFAULT, True)
        self.assertEqual(status, "BLOCKED")
        self.assertIn("cleanup is uncertain", message)

    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh-keygen")
    @patch.object(module, "run_bounded")
    def test_known_host_lookup_is_bounded(self, run, *_):
        run.return_value = subprocess.CompletedProcess([], 0, "pinned-key", "")
        self.assertTrue(module.known_host("/tmp/known_hosts", "192.0.2.10", 22))
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertEqual(run.call_args.kwargs["max_output_bytes"], module.MAX_COMMAND_OUTPUT_BYTES)

    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh-keygen")
    @patch.object(module, "run_bounded")
    def test_known_host_lookup_output_limit_blocks(self, run, *_):
        result = subprocess.CompletedProcess([], 1, "x" * module.MAX_COMMAND_OUTPUT_BYTES, "")
        result.output_limited = True
        run.return_value = result
        with self.assertRaisesRegex(ValueError, "output exceeded"):
            module.known_host("/tmp/known_hosts", "192.0.2.10", 22)

    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh-keygen")
    @patch.object(module, "run_bounded", side_effect=subprocess.TimeoutExpired("ssh-keygen", 5))
    def test_known_host_lookup_timeout_propagates_to_blocked_result(self, run, *_):
        with patch.object(module, "safe_file", return_value="/tmp/known_hosts"):
            status, _ = module.check_node(NODE, DEFAULT, False)
        self.assertEqual(status, "BLOCKED")
        run.assert_called_once()

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh")
    @patch.object(module, "run_bounded")
    def test_trusted_ssh_unavailable_blocks_before_dispatch(self, run, trusted, *_):
        trusted.return_value = None
        status, message = module.check_node(NODE, DEFAULT, True)
        self.assertEqual(status, "BLOCKED")
        self.assertIn("unavailable", message)
        run.assert_not_called()

    @patch.object(module.shutil, "which", return_value="/tmp/ssh")
    def test_user_path_executable_is_not_trusted(self, which):
        self.assertIsNone(module.trusted_executable("ssh"))
        self.assertEqual(which.call_args.kwargs["path"], module.SYSTEM_PATH)

    def test_known_hosts_and_identity_size_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large"
            with path.open("wb") as output:
                output.truncate(module.MAX_KNOWN_HOSTS_BYTES + 1)
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "byte limit"):
                module.safe_file(str(path), "known_hosts")
            with path.open("wb") as output:
                output.truncate(module.MAX_IDENTITY_BYTES + 1)
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "byte limit"):
                module.safe_file(str(path), "identity", private=True)

    def test_private_identity_permissions_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key"
            path.write_text("not a real key")
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "permissions too broad"):
                module.safe_file(str(path), "identity", private=True)

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module, "trusted_executable", return_value="/usr/bin/ssh")
    @patch.object(module, "run_bounded")
    def test_ssh_error_blocks(self, run, *_):
        run.return_value = subprocess.CompletedProcess(
            [], 255, "", "failure"
        )
        status, _ = module.check_node(NODE, DEFAULT, True)
        self.assertEqual(status, "BLOCKED")

    @patch.object(module, "known_host", return_value=True)
    @patch.object(module, "safe_file", return_value="/tmp/known_hosts")
    @patch.object(module, "run_bounded")
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
