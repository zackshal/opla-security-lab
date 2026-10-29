import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("opla_network", ROOT / "bin/opla_network.py")
network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(network)


class NetworkAllocatorTests(unittest.TestCase):
    def test_default_route_gateway_occupies_its_lab_slash29(self):
        subnet = network.select_free_subnet([
            {"dst": "default", "gateway": "100.64.0.1", "dev": "tun0"},
        ])
        self.assertEqual(str(subnet), "100.64.0.8/29")

    def test_exclusion_also_skips_default_gateway_network(self):
        subnet = network.select_free_subnet(
            [{"dst": "default", "gateway": "100.64.0.1", "dev": "tun0"}],
            excluded="100.64.0.8/29",
        )
        self.assertEqual(str(subnet), "100.64.0.16/29")

    def test_ipv6_gateway_does_not_consume_ipv4_pool(self):
        subnet = network.select_free_subnet([
            {"dst": "default", "gateway": "fe80::1", "dev": "tun0"},
        ])
        self.assertEqual(str(subnet), "100.64.0.0/29")

    def test_route_destination_inside_pool_is_excluded(self):
        subnet = network.select_free_subnet([
            {"dst": "100.64.0.0/29", "dev": "some0"},
        ])
        self.assertEqual(str(subnet), "100.64.0.8/29")

    def test_stopped_lab_state_reserves_both_networks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lab = root / "lab-Old12345"
            lab.mkdir(mode=0o700)
            state = lab / "state.env"
            state.write_text(
                "LAB_ID=lab-Old12345\nSUBNET=100.64.0.0/29\n"
                "MGMT_SUBNET=100.64.0.8/29\n",
                encoding="utf-8",
            )
            state.chmod(0o600)
            reserved = network.read_reserved_subnets(root)
            subnet = network.select_free_subnet([], reserved=reserved)
        self.assertEqual(str(subnet), "100.64.0.16/29")

    def test_incomplete_existing_network_state_blocks_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lab = root / "lab-Broken123"
            lab.mkdir(mode=0o700)
            state = lab / "state.env"
            state.write_text("LAB_ID=lab-Else123\nSUBNET=100.64.0.0/29\n")
            state.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "incomplete existing lab network state"):
                network.read_reserved_subnets(root)

    def test_unsafe_existing_state_blocks_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lab = root / "lab-Old12345"
            lab.mkdir(mode=0o700)
            target = root / "state-target"
            target.write_text("LAB_ID=lab-Old12345\nSUBNET=100.64.0.0/29\n")
            (lab / "state.env").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "unsafe existing lab state"):
                network.read_reserved_subnets(root)

    def test_malformed_gateway_fails_closed(self):
        for gateway in (None, "not-an-ip"):
            with self.subTest(gateway=gateway):
                with self.assertRaisesRegex(ValueError, "malformed route gateway"):
                    network.select_free_subnet([
                        {"dst": "default", "gateway": gateway, "dev": "tun0"},
                    ])

    def test_present_null_or_empty_destination_fails_closed(self):
        for destination in (None, ""):
            with self.subTest(destination=destination):
                with self.assertRaisesRegex(ValueError, "malformed route destination"):
                    network.select_free_subnet([{"dst": destination}])

    def test_duplicate_route_json_keys_are_rejected(self):
        with patch.object(network, "trusted_ip_path", return_value=Path("/usr/bin/ip")), \
                patch.object(network, "_bounded_capture", return_value=(
                    b'[{"dst":"100.64.0.0/29","dst":"192.0.2.0/24"}]')):
            with self.assertRaisesRegex(ValueError, "duplicate object key"):
                network.read_ipv4_routes()

    def test_excessively_nested_route_json_is_normalized(self):
        payload = b"[" + b"[" * 10000 + b"0" + b"]" * 10000 + b"]"
        with patch.object(network, "trusted_ip_path", return_value=Path("/usr/bin/ip")), \
                patch.object(network, "_bounded_capture", return_value=payload):
            with self.assertRaisesRegex(ValueError, "route table JSON is malformed"):
                network.read_ipv4_routes()

    def test_oversized_child_output_is_stopped_at_limit(self):
        code = "import os; os.write(1, b'x' * 1048576)"
        with self.assertRaisesRegex(ValueError, "output exceeds limit"):
            network._bounded_capture([sys.executable, "-c", code], timeout=2)

    def test_child_timeout_is_bounded_and_cleaned_up(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            network._bounded_capture([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05)

    def test_cleanup_signals_group_even_if_leader_already_exited(self):
        process = Mock(pid=4242)
        process.wait.return_value = 0
        with patch.object(network.os, "killpg", side_effect=[None, ProcessLookupError]) as killpg:
            network._stop_owned_process(process)
        self.assertEqual(killpg.call_args_list, [call(4242, network.signal.SIGTERM), call(4242, 0)])

    def test_both_shell_allocators_are_bound_to_shared_helper(self):
        source = (ROOT / "bin/lib.sh").read_text(encoding="utf-8")
        self.assertIn('python3 "$SCRIPT_DIR/opla_network.py" --exclude-subnet "$excluded"', source)
        self.assertIn('python3 "$SCRIPT_DIR/opla_network.py"', source)
        self.assertNotIn("ip -j -4 route show table all", source)


if __name__ == "__main__":
    unittest.main()
