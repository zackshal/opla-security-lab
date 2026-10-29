"""Safety contracts for OPLA live scenario adapter."""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/opla-scenario-live.py"

spec = importlib.util.spec_from_file_location("opla_scenario_live", SCRIPT)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class LiveScenarioTests(unittest.TestCase):

    def test_registry_inspection_uses_only_trusted_read_only_helper(self):
        state = {
            key: value for key, value in zip(
                ("LAB_ID", "BRIDGE", "SUBNET", "GW", "ATTACKER_IP", "VICTIM_IP",
                 "CLIENT_IP", "MGMT_BRIDGE", "MGMT_SUBNET", "MGMT_GW",
                 "ATTACKER_MGMT_IP", "VICTIM_MGMT_IP", "CLIENT_MGMT_IP"),
                ("lab-Ab12", "br-op2", "100.64.0.0/29", "100.64.0.1",
                 "100.64.0.2", "100.64.0.3", "100.64.0.4", "br-op3",
                 "100.64.0.8/29", "100.64.0.9", "100.64.0.10",
                 "100.64.0.11", "100.64.0.12"),
            )
        }
        record = [{
            "file": "lab-Ab12.json", "lab": "lab-Ab12",
            "status": "recorded", "resources": 20, "state": state,
        }]
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, json.dumps(record), "")

        with patch.object(live, "validate_trusted_registry_helper", return_value=Path("/opt/opla/bin/opla-registry.py")):
            result = live.inspect_registry("lab-Ab12", 20, runner=runner)

        self.assertEqual(result["status"], "recorded")
        self.assertEqual(calls[0][0], [
            "sudo", "/opt/opla/bin/opla-registry.py", "list", "--lab", "lab-Ab12",
        ])
        self.assertEqual(calls[0][1]["timeout"], 10)
        self.assertFalse(calls[0][1]["check"])

    def test_registry_inspection_rejects_stale_or_mismatched_receipts(self):
        for record in (
            [{"file": "lab-Ab12.json", "lab": "lab-Ab12", "status": "incomplete", "resources": 20}],
            [{"file": "lab-Ab12.json", "lab": "lab-Ab12", "status": "recorded", "resources": 19}],
            [{"file": "lab-Else.json", "lab": "lab-Else", "status": "recorded", "resources": 20}],
            [],
        ):
            with self.subTest(record=record), \
                 patch.object(live, "validate_trusted_registry_helper", return_value=Path("/opt/opla/bin/opla-registry.py")), \
                 self.assertRaises(RuntimeError):
                live.inspect_registry(
                    "lab-Ab12", 20,
                    runner=lambda argv, **kwargs: subprocess.CompletedProcess(
                        argv, 0, json.dumps(record), ""),
                )

    def test_registry_inspection_rejects_failed_or_oversized_helper_output(self):
        with patch.object(live, "validate_trusted_registry_helper", return_value=Path("/opt/opla/bin/opla-registry.py")):
            with self.assertRaisesRegex(RuntimeError, "inspection failed"):
                live.inspect_registry(
                    "lab-Ab12", 20,
                    runner=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, "", "denied"),
                )
            with self.assertRaisesRegex(RuntimeError, "too large"):
                live.inspect_registry(
                    "lab-Ab12", 20,
                    runner=lambda argv, **kwargs: subprocess.CompletedProcess(
                        argv, 0, " " * (live.MAX_REGISTRY_OUTPUT_BYTES + 1), ""),
                )

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

    def test_debian_12_and_13_are_supported_when_administrator_opted_in(self):
        for version in ("12", "13"):
            with self.subTest(version=version):
                live.validate_executor_requirements(
                    f'ID=debian\nVERSION_ID="{version}"\n',
                    True,
                    "MemTotal:       8388608 kB\n",
                )

    def test_non_root_operator_can_use_explicitly_authorized_executor(self):
        original_read_text = Path.read_text

        def read_text(path, *args, **kwargs):
            if path == Path("/etc/os-release"):
                return 'ID=debian\nVERSION_ID="13"\n'
            if path == Path("/proc/meminfo"):
                return "MemTotal:       8388608 kB\n"
            return original_read_text(path, *args, **kwargs)

        with patch.object(live.os, "geteuid", return_value=1000), \
             patch.object(Path, "read_text", read_text), \
             patch.object(live, "read_executor_authorization", return_value=True):
            live.executor_authorized()

    def test_unsupported_os_or_insufficient_memory_still_blocks(self):
        for os_release, memory, expected in (
                ('ID=debian\nVERSION_ID="11"\n', "MemTotal: 8388608 kB", "Debian 12 or Debian 13"),
                ('ID=ubuntu\nVERSION_ID="24.04"\n', "MemTotal: 8388608 kB", "Debian 12 or Debian 13"),
                ('ID=debian\nVERSION_ID="13"\n', "MemTotal: 4096 kB", "at least 5 GiB")):
            with self.subTest(os_release=os_release, memory=memory), \
                 self.assertRaisesRegex(RuntimeError, expected):
                live.validate_executor_requirements(os_release, True, memory)

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
