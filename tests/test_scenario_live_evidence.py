import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    import yaml  # noqa: F401
except ImportError:
    raise unittest.SkipTest("PyYAML unavailable; scenario YAML tests skipped")

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_scenario_live_evidence_test",
    ROOT / "bin/opla-scenario-live.py",
)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
import opla_process


class LiveEvidenceTests(unittest.TestCase):

    def test_syn_scan_invokes_existing_traffic_script(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="Материалы опыта: reports/scenario-syn-ABCDEFGH\n",
            stderr="",
        )
        expected_evidence = {
            "telemetry_collected": True,
            "deltas": {"syn": 15, "drop": 0},
            "scan_detected": None,
        }

        with patch.object(live, "call", return_value=result) as call, \
             patch.object(
                 live,
                 "read_scan_evidence",
                 return_value=expected_evidence,
             ):
            item = live.run_stage(
                {"id": "scan", "kind": "syn-scan"},
                {},
                {},
            )

        self.assertEqual(call.call_args.args[0], [
            "bash", "bin/traffic-scenario.sh", "syn"
        ])
        self.assertEqual(item["status"], "completed")
        self.assertEqual(item["evidence"], expected_evidence)

    def test_missing_evidence_fails_stage(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="Generator finished, no snapshots",
            stderr="",
        )

        with patch.object(live, "call", return_value=result):
            item = live.run_stage(
                {"id": "scan", "kind": "syn-scan"},
                {},
                {},
            )

        self.assertEqual(item["status"], "failed")
        self.assertIn("evidence_error", item)

    def test_http_uses_client_and_checks_http_errors(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="HTTP=200\n",
            stderr="",
        )
        addresses = {
            "client": "192.0.2.3",
            "victim": "192.0.2.4",
        }

        with patch.object(live, "call", return_value=result) as call:
            item = live.run_stage(
                {"id": "availability", "kind": "http-probe"},
                {},
                addresses,
            )

        self.assertEqual(item["status"], "completed")
        command = call.call_args.args[0]
        self.assertEqual(command[:2], ["bash", "-c"])
        self.assertIn("--fail", command[2])
        self.assertIn("OPLA_CLIENT_IP", command[2])
        self.assertEqual(
            call.call_args.kwargs["env"]["OPLA_CLIENT_IP"],
            addresses["client"],
        )

    def test_http_redirect_is_not_success(self):
        result = SimpleNamespace(returncode=0, stdout="HTTP=302\n", stderr="")
        with patch.object(live, "call", return_value=result):
            item = live.run_stage(
                {"id": "availability", "kind": "http-probe"},
                {},
                {"client": "192.0.2.3", "victim": "192.0.2.4"},
            )
        self.assertEqual(item["status"], "failed")
        self.assertIn("exactly HTTP 200", item["error"])

    def test_malformed_http_probe_output_is_not_success(self):
        result = SimpleNamespace(returncode=0, stdout="connected\nHTTP=200 extra\n", stderr="")
        with patch.object(live, "call", return_value=result):
            item = live.run_stage(
                {"id": "availability", "kind": "http-probe"},
                {},
                {"client": "192.0.2.3", "victim": "192.0.2.4"},
            )
        self.assertEqual(item["status"], "failed")

    def test_stage_output_is_capped_and_reported_as_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = os.path.join(temporary, "side-artifact")
            command = (
                "import os; open(%r,'wb').write(b'z'*32768); "
                "os.write(1,b'x'*100000)"
            ) % artifact
            result = live.call([sys.executable, "-c", command], timeout=5)
            self.assertTrue(result.output_limited)
            self.assertLessEqual(len(result.stdout.encode()), live.MAX_STAGE_OUTPUT_BYTES)
            self.assertEqual(os.path.getsize(artifact), 32768)
            with patch.object(live, "call", return_value=result):
                item = live.run_stage({"id": "observe", "kind": "xdp-observe"}, {}, {})
            self.assertEqual(item["status"], "failed")
            self.assertIn("output reached", item["error"])

    def test_timeout_terminates_owned_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = os.path.join(temporary, "child.pid")
            child = (
                "import os,signal,subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)']); "
                f"open({pid_path!r},'w').write(str(p.pid)); time.sleep(30)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                live.call([sys.executable, "-c", child], timeout=0.2)
            with open(pid_path, encoding="ascii") as stream:
                child_pid = int(stream.read())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    with open(f"/proc/{child_pid}/stat", encoding="ascii") as stream:
                        state = stream.read().split()[2]
                except FileNotFoundError:
                    break
                if state == "Z":
                    break
                time.sleep(0.02)
            else:
                self.fail("owned stage descendant remained active after timeout cleanup")

    def test_persistent_group_after_kill_is_reported_for_reconciliation(self):
        class FakeProcess:
            pid = 8765

            def wait(self, timeout=None):
                return 0

        with patch.object(opla_process.os, "killpg") as killpg, \
                patch.object(opla_process, "_group_exists", side_effect=(True, True)):
            error = opla_process.terminate_owned_group(FakeProcess(), grace=0)
        self.assertIn("remains after termination", error)
        self.assertEqual(killpg.call_count, 2)


if __name__ == "__main__":
    unittest.main()
