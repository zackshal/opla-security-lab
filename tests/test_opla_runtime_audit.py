import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
import io
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opla_runtime_audit", ROOT / "bin/opla-runtime-audit.py"
)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class RuntimeAuditTests(unittest.TestCase):
    def test_static_inventory_maps_all_runtime_components_without_live_claim(self):
        report = audit.build_report()
        self.assertEqual(report["mode"], "static")
        self.assertFalse(report["execution_performed"])
        self.assertFalse(report["host_mutated"])
        self.assertEqual(report["overall_status"], "NOT TESTED")
        self.assertEqual(len(report["components"]), 13)
        self.assertIn("host-admission", {item["id"] for item in report["components"]})
        network = next(item for item in report["components"] if item["id"] == "network-management")
        self.assertIn("bin/lib.sh", network["source_sha256"])
        self.assertIn("bin/opla_network.py", network["source_sha256"])
        self.assertTrue(all(item["static_verdict"] == "PASS" for item in report["components"]))
        self.assertTrue(all(item["runtime_verdict"] == "NOT TESTED" for item in report["components"]))
        xdp = next(item for item in report["components"] if item["id"] == "xdp-ebpf")
        self.assertTrue({"xdp/runtime-guard.py", "xdp/load.sh", "xdp/unload.sh",
                         "xdp/scan-policy.py"} <= set(xdp["required_files"]))
        suricata = next(item for item in report["components"] if item["id"] == "suricata-ids")
        scenario = next(item for item in report["components"] if item["id"] == "scenario-engine")
        monitoring = next(item for item in report["components"] if item["id"] == "monitoring")
        self.assertIn("bin/opla_process.py", scenario["entry_points"])
        self.assertIn("bin/opla_process.py", monitoring["entry_points"])
        self.assertTrue({"security/suricata/manage.py", "security/suricata/runtime.py",
                         "security/suricata/nft_policy.py", "security/suricata/ips.rules"}
                        <= set(suricata["required_files"]))
        required = {"component", "requirement", "environment", "host_id", "command",
                    "start_time", "end_time", "exit_status", "expected", "observed",
                    "evidence_path", "verdict", "reason", "reviewer"}
        self.assertTrue(all(required <= set(check) for check in report["checks"]))
        self.assertTrue(all(check["host_id"] is None for check in report["checks"]))

    def test_static_inventory_remains_available_without_posix_resource_module(self):
        with patch.object(audit, "resource", None):
            report = audit.build_report()
            with patch.object(audit, "vetted_command", return_value="/usr/bin/ss"):
                observation = audit.observe_command("ss", [])
        self.assertEqual(report["overall_status"], "NOT TESTED")
        self.assertEqual(observation["verdict"], "BLOCKED")
        self.assertIn("require a POSIX runtime", observation["stderr"])

    def test_missing_source_is_blocked_not_promoted_to_runtime_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries = audit.static_inventory(Path(tmp))
        self.assertTrue(all(entry["static_verdict"] == "BLOCKED" for entry in entries))
        self.assertTrue(all(entry["runtime_verdict"] == "BLOCKED" for entry in entries))

    def test_process_snapshot_records_fd_categories_without_private_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "4242"
            (proc / "fd").mkdir(parents=True)
            (proc / "status").write_text(
                "Name:\topla-worker\nPid:\t4242\nPPid:\t99\nUid:\t1000 1000 1000 1000\n"
                "Gid:\t1000 1000 1000 1000\nThreads:\t4\nVmRSS:\t12 kB\n"
                "VmSize:\t20 kB\nVmSwap:\t0 kB\n", encoding="utf-8"
            )
            (proc / "limits").write_text("Max open files            1024                 4096                 files\n", encoding="utf-8")
            fields = ["S", "99"] + ["0"] * 18
            fields[11], fields[12], fields[19] = "17", "19", "100"
            (proc / "stat").write_text("4242 (opla-worker) " + " ".join(fields) + "\n", encoding="utf-8")
            (proc / "io").write_text("read_bytes: 5\nwrite_bytes: 7\nsyscr: 1\nsyscw: 2\n", encoding="utf-8")
            (proc / "fdinfo").mkdir()
            os.symlink("socket:[77]", proc / "fd" / "3")
            os.symlink("pipe:[88]", proc / "fd" / "4")
            os.symlink("/private/secret-token", proc / "fd" / "5")
            for descriptor in ("3", "4", "5"):
                (proc / "fdinfo" / descriptor).write_text("pos:\t0\nflags:\t02\n", encoding="utf-8")
            snap = audit.process_snapshot(4242, proc_root=Path(tmp))
        self.assertEqual(snap["ppid"], 99)
        self.assertEqual(snap["fd_count"], 3)
        self.assertEqual(snap["fd_kinds"], {"file_or_other": 1, "pipe": 1, "socket": 1})
        self.assertNotIn("secret-token", json.dumps(snap))
        self.assertEqual(snap["rlimit_nofile"], {"soft": "1024", "hard": "4096"})
        self.assertEqual(snap["memory_kib"], {"rss": 12, "size": 20, "swap": 0})
        self.assertEqual(snap["cpu_ticks"], {"user": 17, "system": 19})
        self.assertEqual(snap["io_bytes"], {"read": 5, "write": 7})

    def test_process_snapshot_rejects_pid_reuse_during_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "4242"
            (proc / "fd").mkdir(parents=True)
            (proc / "fdinfo").mkdir()
            (proc / "status").write_text(
                "Name:\tworker\nPid:\t4242\nPPid:\t99\nUid:\t1000 1000 1000 1000\n"
                "Gid:\t1000 1000 1000 1000\nThreads:\t1\n", encoding="utf-8")
            (proc / "limits").write_text("Max open files 1024 4096 files\n", encoding="utf-8")
            (proc / "io").write_text("read_bytes: 0\nwrite_bytes: 0\n", encoding="utf-8")
            values = ["S", "99"] + ["0"] * 18
            values[19] = "100"
            before = "4242 (worker) " + " ".join(values) + "\n"
            values[19] = "101"
            after = "4242 (replacement) " + " ".join(values) + "\n"
            real_read = audit.read_limited
            stat_reads = 0

            def changing_stat(path, limit=audit.MAX_CAPTURE_BYTES):
                nonlocal stat_reads
                if Path(path).name == "stat":
                    stat_reads += 1
                    return before if stat_reads == 1 else after
                return real_read(path, limit)

            with patch.object(audit, "read_limited", side_effect=changing_stat):
                with self.assertRaisesRegex(ValueError, "PID was reused"):
                    audit.process_snapshot(4242, proc_root=Path(tmp))

    def test_live_capture_requires_matching_host_identity_and_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine_id = root / "machine-id"
            machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
            runner = Mock()
            runner.return_value = type("Result", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
            with patch.object(audit, "vetted_command", side_effect=lambda item: "/usr/bin/" + item), \
                    patch.object(audit, "process_snapshot", return_value={"pid": 42, "ppid": 1}), \
                    patch.object(audit, "filesystem_snapshot", return_value={"available_bytes": 1}):
                live = audit.capture_live("a" * 32, [42], proc_root=root,
                                          machine_id_path=machine_id, runner=runner)
            with self.assertRaises(ValueError):
                audit.capture_live("b" * 32, [42], machine_id_path=machine_id)
        self.assertEqual(live["verdict"], "NOT TESTED")
        self.assertEqual(runner.call_count, 2)

    @staticmethod
    def _unit_observation(unit, pid):
        properties = {
            "Id": unit, "LoadState": "loaded", "ActiveState": "active",
            "SubState": "running", "MainPID": str(pid), "ExecMainPID": str(pid),
            "User": "root", "Group": "root", "ControlGroup": "/system.slice/" + unit,
        }
        command = {"argv": ["/usr/bin/systemctl", "show", unit], "exit_status": 0,
                   "stdout": "", "stderr": "", "timed_out": False,
                   "output_truncated": False, "cleanup_error": None, "verdict": "PASS"}
        return {"unit": unit, "verdict": "PASS", "properties": properties,
                "reason": "unit state observed", "command": command}

    def test_selected_unit_is_linked_to_stable_main_pid_snapshot(self):
        unit = "qemu-lab-ABCD-victim.service"
        with tempfile.TemporaryDirectory() as tmp:
            machine_id = Path(tmp) / "machine-id"
            machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
            with patch.object(audit, "observe_systemd_unit", side_effect=[
                    self._unit_observation(unit, 42), self._unit_observation(unit, 42)]), \
                 patch.object(audit, "process_snapshot", return_value={"pid": 42, "ppid": 1}), \
                 patch.object(audit, "filesystem_snapshot", return_value={"available_bytes": 1}), \
                 patch.object(audit, "observe_command", return_value={"argv": [], "exit_status": 0,
                     "stdout": "", "stderr": "", "timed_out": False,
                     "output_truncated": False, "cleanup_error": None, "verdict": "PASS"}):
                live = audit.capture_live("a" * 32, [], units=[unit], proc_root=Path(tmp),
                                          machine_id_path=machine_id)
        self.assertEqual(live["process_observations"][0]["systemd_units"], [unit])
        self.assertEqual(live["systemd_unit_observations"][0]["verdict"], "PASS")

    def test_unit_restart_during_capture_blocks_pid_link(self):
        unit = "qemu-lab-ABCD-victim.service"
        with tempfile.TemporaryDirectory() as tmp:
            machine_id = Path(tmp) / "machine-id"
            machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
            with patch.object(audit, "observe_systemd_unit", side_effect=[
                    self._unit_observation(unit, 42), self._unit_observation(unit, 43)]), \
                 patch.object(audit, "process_snapshot", return_value={"pid": 42, "ppid": 1}), \
                 patch.object(audit, "filesystem_snapshot", return_value={"available_bytes": 1}), \
                 patch.object(audit, "observe_command", return_value={"argv": [], "exit_status": 0,
                     "stdout": "", "stderr": "", "timed_out": False,
                     "output_truncated": False, "cleanup_error": None, "verdict": "PASS"}):
                live = audit.capture_live("a" * 32, [], units=[unit], proc_root=Path(tmp),
                                          machine_id_path=machine_id)
        self.assertEqual(live["systemd_unit_observations"][0]["verdict"], "BLOCKED")
        self.assertEqual(live["process_observations"][0]["verdict"], "BLOCKED")
        report = audit.build_report(live=live)
        self.assertEqual(report["observation_status"], "BLOCKED")
        self.assertTrue(any(check["component"] == "host-observation:systemd-unit:" + unit
                            and check["verdict"] == "BLOCKED" for check in report["checks"]))

    def test_active_unit_without_main_pid_stays_blocked(self):
        unit = "qemu-lab-ABCD-victim.service"
        initial = self._unit_observation(unit, 0)
        with tempfile.TemporaryDirectory() as tmp:
            machine_id = Path(tmp) / "machine-id"
            machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
            with patch.object(audit, "observe_systemd_unit", side_effect=[initial, initial]), \
                 patch.object(audit, "filesystem_snapshot", return_value={"available_bytes": 1}), \
                 patch.object(audit, "observe_command", return_value={"argv": [], "exit_status": 0,
                     "stdout": "", "stderr": "", "timed_out": False,
                     "output_truncated": False, "cleanup_error": None, "verdict": "PASS"}):
                live = audit.capture_live("a" * 32, [], units=[unit], proc_root=Path(tmp),
                                          machine_id_path=machine_id)
        self.assertEqual(live["systemd_unit_observations"][0]["verdict"], "BLOCKED")

    def test_systemd_property_parser_rejects_duplicate_identity(self):
        unit = "qemu-lab-ABCD-victim.service"
        output = "Id=" + unit + "\nId=other.service\n"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit.parse_systemd_properties(output, unit)

    def test_systemd_property_parser_requires_ascii_pid(self):
        unit = "qemu-lab-ABCD-victim.service"
        props = self._unit_observation(unit, 42)["properties"]
        props["MainPID"] = "٤٢"
        output = "\n".join(f"{key}={value}" for key, value in props.items())
        with self.assertRaisesRegex(ValueError, "MainPID"):
            audit.parse_systemd_properties(output, unit)

    def test_unit_names_are_allowlisted_before_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            machine_id = Path(tmp) / "machine-id"
            machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
            with patch.object(audit, "observe_systemd_unit") as inspect:
                with self.assertRaisesRegex(ValueError, "--unit"):
                    audit.capture_live("a" * 32, [], units=["ssh.service"], proc_root=Path(tmp),
                                       machine_id_path=machine_id)
            inspect.assert_not_called()

    def test_unit_allowlist_matches_lab_id_and_builtin_qemu_roles(self):
        for unit in ("qemu-lab-abc-victim.service", "qemu-lab-ABCD-monitor.service",
                     "dhcp-lab-abc.service", "dhcp-lab-" + "A" * 33 + ".service"):
            with tempfile.TemporaryDirectory() as tmp:
                machine_id = Path(tmp) / "machine-id"
                machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
                with patch.object(audit, "observe_systemd_unit") as inspect:
                    with self.assertRaisesRegex(ValueError, "--unit"):
                        audit.capture_live("a" * 32, [], units=[unit], proc_root=Path(tmp),
                                           machine_id_path=machine_id)
                inspect.assert_not_called()

    def test_missing_diagnostic_executable_is_preserved_as_blocked(self):
        runner = Mock()
        runner.return_value = type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with patch.object(audit, "vetted_command", side_effect=[ValueError("ss unavailable"), "/usr/bin/systemctl"]):
            result = audit.observe_command("ss", ["-H", "-ltnup"], runner=runner)
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertIsNone(result["exit_status"])
        self.assertIn("ss unavailable", result["stderr"])
        runner.assert_not_called()

    def test_diagnostic_timeout_is_preserved_as_blocked(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
        with patch.object(audit, "vetted_command", return_value="/usr/bin/ss"):
            result = audit.observe_command("ss", ["-H", "-ltnup"], runner=timeout)
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertIsNone(result["exit_status"])
        self.assertIn("TimeoutExpired", result["stderr"])

    def test_diagnostic_output_is_limited_during_child_execution(self):
        size = audit.MAX_CAPTURE_BYTES + 4096
        result = audit.run_read_only([
            sys.executable, "-c", f"import sys; sys.stdout.write('x' * {size})",
        ])
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(len(result["stdout"].encode()), audit.MAX_CAPTURE_BYTES)

    def test_timeout_cleanup_reap_wait_is_finite_and_failure_is_blocked(self):
        class StuckProcess:
            pid = 789
            def __init__(self):
                self.wait_timeouts = []
            def wait(self, timeout=None):
                self.wait_timeouts.append(timeout)
                raise subprocess.TimeoutExpired(["diagnostic"], timeout)
            def kill(self):
                raise PermissionError("kill refused")

        process = StuckProcess()
        with patch.object(audit.subprocess, "Popen", return_value=process), \
                patch.object(audit.os, "killpg", side_effect=PermissionError("group kill refused")):
            result = audit.bounded_diagnostic_runner(["diagnostic"], timeout=0.01)
        self.assertEqual(process.wait_timeouts, [0.01, audit.COMMAND_REAP_TIMEOUT_SECONDS])
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertIn("was not reaped", result.cleanup_error)
        with patch.object(audit, "bounded_diagnostic_runner", return_value=result):
            self.assertEqual(audit.run_read_only(["diagnostic"])["verdict"], "BLOCKED")

    def test_group_kill_failure_remains_in_evidence_after_process_fallback(self):
        class ExitsAfterFallback:
            pid = 790
            def __init__(self):
                self.wait_count = 0
                self.killed = False
            def wait(self, timeout=None):
                self.wait_count += 1
                if self.wait_count == 1:
                    raise subprocess.TimeoutExpired(["diagnostic"], timeout)
                return -9
            def kill(self):
                self.killed = True

        process = ExitsAfterFallback()
        with patch.object(audit.subprocess, "Popen", return_value=process), \
                patch.object(audit.os, "killpg", side_effect=PermissionError("group kill denied")):
            result = audit.bounded_diagnostic_runner(["diagnostic"], timeout=0.01)
        self.assertTrue(process.killed)
        self.assertEqual(result.returncode, 124)
        self.assertIn("group kill denied", result.cleanup_error)
        with patch.object(audit, "bounded_diagnostic_runner", return_value=result):
            self.assertEqual(audit.run_read_only(["diagnostic"])["verdict"], "BLOCKED")

    def test_live_capture_preserves_unreadable_process_and_continues(self):
        with tempfile.TemporaryDirectory() as tmp:
            machine_id = Path(tmp) / "machine-id"
            machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
            runner = Mock()
            runner.return_value = type("Result", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
            with patch.object(audit, "process_snapshot", side_effect=ValueError("fd inventory unavailable")), \
                    patch.object(audit, "vetted_command", side_effect=lambda item: "/usr/bin/" + item), \
                    patch.object(audit, "filesystem_snapshot", return_value={"available_bytes": 1}):
                live = audit.capture_live("a" * 32, [42], proc_root=Path(tmp),
                                          machine_id_path=machine_id, runner=runner)
        self.assertEqual(live["processes"], [])
        self.assertEqual(live["process_observations"][0]["verdict"], "BLOCKED")
        self.assertEqual(runner.call_count, 2)
        report = audit.build_report(live=live)
        process_check = next(check for check in report["checks"]
                             if check["component"] == "host-observation:process:42")
        self.assertEqual(process_check["exit_status"], None)
        self.assertEqual(process_check["verdict"], "BLOCKED")
        self.assertEqual(report["overall_status"], "NOT TESTED")

    def test_live_capture_preserves_filesystem_failure_and_continues(self):
        with tempfile.TemporaryDirectory() as tmp:
            machine_id = Path(tmp) / "machine-id"
            machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
            runner = Mock()
            runner.return_value = type("Result", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
            with patch.object(audit, "process_snapshot", return_value={"pid": 42, "ppid": 1}), \
                    patch.object(audit, "filesystem_snapshot", side_effect=OSError("statvfs denied")), \
                    patch.object(audit, "vetted_command", side_effect=lambda item: "/usr/bin/" + item):
                live = audit.capture_live("a" * 32, [42], proc_root=Path(tmp),
                                          machine_id_path=machine_id, runner=runner)
        self.assertIsNone(live["filesystem"])
        self.assertEqual(live["filesystem_observation"]["verdict"], "BLOCKED")
        self.assertEqual(runner.call_count, 2)
        report = audit.build_report(live=live)
        filesystem_check = next(check for check in report["checks"]
                                if check["component"] == "host-observation:filesystem")
        self.assertIsNone(filesystem_check["exit_status"])
        self.assertEqual(filesystem_check["verdict"], "BLOCKED")
        self.assertEqual(report["observation_status"], "BLOCKED")

    def test_capture_live_requires_unique_process_ids(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            audit.capture_live("a" * 32, [], machine_id_path=Path("missing"))
        with self.assertRaisesRegex(ValueError, "unique"):
            audit.capture_live("a" * 32, [1, 1], machine_id_path=Path("missing"))

    def test_live_report_preserves_diagnostic_failures_without_promoting_readiness(self):
        live = {
            "host_id": "a" * 32,
            "processes": [{"pid": 10}],
            "process_observations": [{"pid": 10, "exit_status": 0, "verdict": "PASS", "reason": "snapshot collected"}],
            "reason": "snapshot collected",
            "filesystem": {"available_bytes": 1},
            "filesystem_observation": {"exit_status": 0, "verdict": "PASS", "reason": "collected"},
            "listening_sockets": {"argv": ["/usr/bin/ss", "-H", "-ltnup"],
                                  "exit_status": 0, "stdout": "LISTEN", "stderr": "", "verdict": "PASS"},
            "systemd_units": {"argv": ["/usr/bin/systemctl", "list-units"],
                              "exit_status": 1, "stdout": "", "stderr": "access denied", "verdict": "BLOCKED"},
        }
        report = audit.build_report(live=live)
        checks = {check["component"]: check for check in report["checks"]}
        failed = checks["host-observation:systemd_units"]
        self.assertEqual(failed["exit_status"], 1)
        self.assertEqual(failed["verdict"], "BLOCKED")
        self.assertEqual(failed["observed"]["stderr"], "access denied")
        self.assertEqual(report["observation_status"], "BLOCKED")
        self.assertEqual(report["overall_status"], "NOT TESTED")
        summary = checks["host-observation-report"]
        self.assertEqual(summary["verdict"], "BLOCKED")
        self.assertEqual(summary["exit_status"], 2)

    def test_successful_observation_probes_do_not_claim_functional_readiness(self):
        live = {
            "host_id": "a" * 32, "processes": [], "reason": "snapshot collected",
            "process_observations": [],
            "filesystem": {"available_bytes": 1},
            "filesystem_observation": {"exit_status": 0, "verdict": "PASS", "reason": "collected"},
            "listening_sockets": {"argv": ["ss"], "exit_status": 0, "stdout": "", "stderr": "", "verdict": "PASS"},
            "systemd_units": {"argv": ["systemctl"], "exit_status": 0, "stdout": "", "stderr": "", "verdict": "PASS"},
        }
        report = audit.build_report(live=live)
        self.assertEqual(report["observation_status"], "PASS")
        self.assertEqual(report["overall_status"], "NOT TESTED")
        self.assertTrue(all(check["verdict"] == "PASS"
                            for check in report["checks"]
                            if check["component"].startswith("host-observation:")))

    def test_cli_returns_blocked_for_failed_observation_probe_and_saves_evidence(self):
        live = {
            "host_id": "a" * 32, "processes": [{"pid": 10}], "reason": "snapshot collected",
            "process_observations": [{"pid": 10, "exit_status": 0, "verdict": "PASS", "reason": "snapshot collected"}],
            "filesystem": {"available_bytes": 1},
            "filesystem_observation": {"exit_status": 0, "verdict": "PASS", "reason": "collected"},
            "listening_sockets": {"argv": ["ss"], "exit_status": 0, "stdout": "", "stderr": "", "verdict": "PASS"},
            "systemd_units": {"argv": ["systemctl"], "exit_status": 0, "stdout": "", "stderr": "", "verdict": "PASS"},
            "systemd_unit_observations": [{"unit": "qemu-lab-ABCD-victim.service",
                "initial": {"properties": {"MainPID": "10"}, "command": {"argv": ["systemctl", "show"], "exit_status": 0}},
                "final": None, "verdict": "BLOCKED", "reason": "unit changed during capture"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "capture.json"
            output = io.StringIO()
            with patch.object(audit, "capture_live", return_value=live), redirect_stdout(output):
                result = audit.main([
                    "--capture-live", "--authorized-host-id", "a" * 32,
                    "--i-accept-read-only-host-inspection", "--pid", "10",
                    "--output", str(destination),
                ])
            saved = json.loads(destination.read_text())
        self.assertEqual(result, 2)
        self.assertEqual(saved["observation_status"], "BLOCKED")
        self.assertEqual(saved["overall_status"], "NOT TESTED")
        self.assertIn("systemd-unit:qemu-lab-ABCD-victim.service", output.getvalue())

    def test_evidence_output_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            report = audit.build_report(evidence_path=path)
            audit.write_report(path, report)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["schema_version"], 1)
            self.assertEqual(audit.verify_report(path)["verification_status"], "PASS")
            with self.assertRaises(ValueError):
                audit.write_report(path, report)

    def test_report_verification_blocks_changed_component_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            report = audit.build_report()
            report["components"][0]["source_sha256"] = {"changed": "0" * 64}
            audit.write_report(path, report)
            verified = audit.verify_report(path)
        self.assertEqual(verified["verification_status"], "BLOCKED")
        self.assertEqual(verified["changed_components"], ["control-plane", "report-semantics"])

    def test_report_verification_rejects_forged_runtime_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            report = audit.build_report()
            report["overall_status"] = "PASS"
            report["components"][0]["runtime_verdict"] = "PASS"
            audit.write_report(path, report)
            verified = audit.verify_report(path)
        self.assertEqual(verified["verification_status"], "BLOCKED")
        self.assertEqual(verified["runtime_status"], "PASS")
        self.assertIn("report-semantics", verified["changed_components"])

    def test_limited_read_rejects_oversized_file_without_returning_a_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oversized"
            path.write_bytes(b"x" * 33)
            with self.assertRaises(ValueError):
                audit.read_limited(path, 32)

    def test_static_inventory_rejects_symlinked_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.write_text("source", encoding="utf-8")
            linked = root / "bin" / "opla-cli.py"
            linked.parent.mkdir()
            linked.symlink_to(outside)
            records = audit.static_inventory(root)
        control = next(record for record in records if record["id"] == "control-plane")
        self.assertEqual(control["static_verdict"], "BLOCKED")
        self.assertIn("bin/opla-cli.py", control["reason"])

    def test_static_inventory_rejects_symlinked_source_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "opla-cli.py").write_text("source", encoding="utf-8")
            (root / "bin").symlink_to(outside, target_is_directory=True)
            records = audit.static_inventory(root)
        control = next(record for record in records if record["id"] == "control-plane")
        self.assertEqual(control["static_verdict"], "BLOCKED")
        self.assertIn("bin/opla-cli.py", control["reason"])

    def test_process_snapshot_rejects_symlinked_proc_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real").mkdir()
            (root / "proc").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(ValueError):
                audit.process_snapshot(1, proc_root=root / "proc")

    def test_write_rejects_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(ValueError):
                audit.write_report(root / "link" / "report.json", audit.build_report())

    def test_report_verification_rejects_forged_check_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            report = audit.build_report(evidence_path=path)
            report["checks"][0]["command"] = "forged command"
            audit.write_report(path, report)
            verified = audit.verify_report(path)
        self.assertEqual(verified["verification_status"], "BLOCKED")
        self.assertIn("report-semantics", verified["changed_components"])

    def test_report_verification_rejects_naive_or_reverse_timestamps(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            report = audit.build_report(evidence_path=path)
            report["created_at"] = "2026-10-28T00:00:00"
            report["checks"][0]["start_time"] = "2026-10-28T01:00:00+00:00"
            report["checks"][0]["end_time"] = "2026-10-28T00:00:00+00:00"
            audit.write_report(path, report)
            verified = audit.verify_report(path)
        self.assertEqual(verified["verification_status"], "BLOCKED")
        self.assertIn("report-semantics", verified["changed_components"])

    def test_snapshot_comparison_reports_deltas_without_claiming_a_leak(self):
        def live(fd_count, read_bytes):
            return {
                "host_id": "a" * 32,
                "processes": [{"pid": 10, "name": "qemu", "threads": 2,
                               "fd_count": fd_count, "memory_kib": {"rss": 1},
                               "cpu_ticks": {"user": 2}, "io_bytes": {"read": read_bytes},
                               "fd_kinds": {"socket": fd_count}}],
                "filesystem": {"available_bytes": 10}, "reason": "fixture",
            }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_path, candidate_path = root / "baseline.json", root / "candidate.json"
            audit.write_report(baseline_path, audit.build_report(live=live(3, 4), evidence_path=baseline_path))
            audit.write_report(candidate_path, audit.build_report(live=live(5, 8), evidence_path=candidate_path))
            comparison = audit.compare_live_observations(baseline_path, candidate_path)
        self.assertEqual(comparison["verdict"], "NOT TESTED")
        self.assertEqual(comparison["new_pids"], [])
        self.assertEqual(comparison["process_changes"][0]["pid"], 10)
        self.assertIn("fd_count", comparison["process_changes"][0]["changes"])

    def test_snapshot_comparison_blocks_mismatched_host_identity(self):
        def report(path, host):
            live = {"host_id": host, "processes": [], "filesystem": {}, "reason": "fixture"}
            return audit.build_report(live=live, evidence_path=path)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / "one.json", root / "two.json"
            audit.write_report(first, report(first, "a" * 32))
            audit.write_report(second, report(second, "b" * 32))
            with self.assertRaises(ValueError):
                audit.compare_live_observations(first, second)


if __name__ == "__main__":
    unittest.main()
