import importlib.util
import json
import io
from types import SimpleNamespace
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("host_admission", ROOT / "bin/opla-host-admission.py")
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def report(*, memory=6_000_000, kvm="PRESENT", routes="PRESENT", docker="PRESENT", filesystems=None):
    return {"schema_version": 1, "kind": "opla_host_admission",
            "collector": {"name": "opla-host-admission", "source_sha256": "b" * 64},
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "host": {"machine_id": "a" * 32, "hostname": "test", "system": "Linux",
                     "release": "test-kernel", "architecture": "x86_64",
                     "distribution_id": "debian", "distribution_version": "13"},
            "execution_scope": {"visibility": "PID1_NAMESPACE_MATCH", "namespaces": {
                "mnt": "SAME", "pid": "SAME", "net": "SAME", "user": "SAME"},
                "physical_machine_type": "NOT TESTED"},
            "collection_context": "user_terminal", "read_only": True,
            "evidence": {"cpu": {"status": "PRESENT", "architecture": "x86_64", "logical_cpus": 8,
                                  "virtualization_flag": "vmx", "virtualization_status": "PRESENT"}, "kvm": {"status": kvm},
                         "memory": {"values_kib": {"MemAvailable": memory}},
                         "filesystems": filesystems if filesystems is not None else {"status": "PRESENT", "requested_path": "/var/lib/opla", "stdout": "Filesystem Type 1B-blocks Used Available Use% Mounted\n/dev/test ext4 50000000000 1 40000000000 1% /\n"},
                         "network": {"routes": {"status": routes, "stdout": '[{"dst":"192.0.2.0/24"}]'}, "addresses": {"status": "PRESENT", "stdout": '[{"addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":24}]}]'}},
                         "processes": {"status": "PRESENT", "stdout": "1 0 root S init"},
                         "services": {"status": "PRESENT", "stdout": "systemd.service loaded active running"},
                         "listeners": {"status": "PRESENT", "stdout": ""},
                         "docker": {"networks": {"status": docker, "stdout": "[]",
                                                    "host_inventory_complete": True}},
                         "tools": {name: {"status": "PRESENT"} for name in ("qemu-system-x86_64", "qemu-img", "cloud-localds", "dnsmasq", "ip", "nft", "flock", "python3", "systemd-run", "systemctl", "ssh")},
                         "security": {"uid": 1000, "effective_uid": 1000}}}


def admitted(data, expected="a" * 32):
    return admission.validate(data, expected, confirm_host_terminal=expected,
                              expected_collector_sha256="b" * 64)


class HostAdmissionTests(unittest.TestCase):
    def test_os_release_is_parsed_as_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "os-release"
            path.write_text('ID=debian\nVERSION_ID="13"\nRUN=ignored\n', encoding="utf-8")
            self.assertEqual(admission.read_os_release(path), {"ID": "debian", "VERSION_ID": "13"})

    def test_duplicate_os_release_keys_are_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "os-release"
            path.write_text("ID=debian\nID=ubuntu\nVERSION_ID=13\nVERSION_ID=24.04\n", encoding="utf-8")
            self.assertEqual(admission.read_os_release(path), {})

    def test_malformed_os_release_key_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "os-release"
            path.write_text("ID=debian\nVERSION_ID='unterminated\n", encoding="utf-8")
            self.assertEqual(admission.read_os_release(path), {"ID": "debian"})

    def test_unvalidated_distribution_stays_unknown_not_rejected(self):
        data = report()
        data["host"]["distribution_id"] = "ubuntu"
        data["host"]["distribution_version"] = "24.04"
        decision = admitted(data)
        self.assertEqual(decision["sandbox_capability_assessment"], "UNKNOWN")
        self.assertTrue(any("no validated built-in host profile" in reason for reason in decision["reasons"]))

    def test_missing_distribution_identity_stays_unknown(self):
        data = report()
        del data["host"]["distribution_version"]
        decision = admitted(data)
        self.assertEqual(decision["sandbox_capability_assessment"], "UNKNOWN")
        self.assertTrue(any("distribution identity or version unavailable" in reason
                            for reason in decision["reasons"]))

    def test_insufficient_ram_is_rejected(self):
        self.assertEqual(admitted(report(memory=5_000_000))["status"], "REJECTED")

    def test_limited_namespace_does_not_reject_physical_host(self):
        data = report(memory=1, kvm="ABSENT")
        data["execution_scope"]["visibility"] = "NAMESPACE_LIMITED"
        data["execution_scope"]["namespaces"]["net"] = "DIFFERENT"
        result = admitted(data)
        self.assertEqual(result["sandbox_capability_assessment"], "REJECTED")
        self.assertEqual(result["host_assessment"], "NOT TESTED")
        self.assertEqual(result["status"], "NOT TESTED")

    def test_unverified_scope_does_not_admit_host(self):
        data = report()
        data["execution_scope"]["visibility"] = "UNKNOWN"
        data["execution_scope"]["namespaces"]["user"] = "UNKNOWN"
        result = admitted(data)
        self.assertEqual(result["sandbox_capability_assessment"], "UNKNOWN")
        self.assertEqual(result["host_assessment"], "NOT TESTED")

    def test_host_assessment_requires_explicit_matching_terminal_confirmation(self):
        data = report(kvm="ABSENT")
        without = admission.validate(data, "a" * 32)
        self.assertEqual(without["sandbox_capability_assessment"], "REJECTED")
        self.assertEqual(without["host_assessment"], "NOT TESTED")
        with_confirmation = admission.validate(data, "a" * 32, confirm_host_terminal="a" * 32,
                                               expected_collector_sha256="b" * 64)
        self.assertEqual(with_confirmation["host_assessment"], "REJECTED")
        with self.assertRaisesRegex(ValueError, "confirmation differs"):
            admission.validate(data, "a" * 32, confirm_host_terminal="b" * 32,
                               expected_collector_sha256="b" * 64)

    def test_collector_fingerprint_must_match_independent_pin(self):
        with self.assertRaisesRegex(ValueError, "fingerprint differs"):
            admission.validate(report(), "a" * 32, confirm_host_terminal="a" * 32,
                               expected_collector_sha256="c" * 64)

    def test_missing_collector_pin_keeps_host_assessment_not_tested(self):
        result = admission.validate(report(), "a" * 32, confirm_host_terminal="a" * 32)
        self.assertEqual(result["sandbox_capability_assessment"], "CONDITIONALLY ADMITTED")
        self.assertEqual(result["host_assessment"], "NOT TESTED")
        self.assertEqual(result["provenance"]["collector_fingerprint"], "NOT TESTED")

    def test_namespace_visibility_does_not_claim_physical_machine_type(self):
        with patch.object(admission.os, "readlink", side_effect=lambda path: {
            "/proc/self/ns/mnt": "mnt:[1]", "/proc/1/ns/mnt": "mnt:[1]",
            "/proc/self/ns/pid": "pid:[2]", "/proc/1/ns/pid": "pid:[2]",
            "/proc/self/ns/net": "net:[3]", "/proc/1/ns/net": "net:[3]",
            "/proc/self/ns/user": "user:[4]", "/proc/1/ns/user": "user:[4]",
        }[path]):
            scope = admission.namespace_visibility()
        self.assertEqual(scope["visibility"], "PID1_NAMESPACE_MATCH")
        self.assertEqual(scope["physical_machine_type"], "NOT TESTED")

    def test_import_rejects_forged_physical_machine_type(self):
        data = report()
        data["execution_scope"]["physical_machine_type"] = "bare metal"
        with self.assertRaisesRegex(ValueError, "must remain NOT TESTED"):
            admitted(data)

    def test_root_or_setuid_export_is_not_labelled_user_terminal(self):
        with patch.object(admission.os, "getuid", return_value=0), \
             patch.object(admission.os, "geteuid", return_value=0):
            self.assertEqual(admission.collection_context(), "privileged_or_setuid_terminal")
        with patch.object(admission.os, "getuid", return_value=1000), \
             patch.object(admission.os, "geteuid", return_value=1000), \
             patch.object(admission.os, "isatty", return_value=True):
            self.assertEqual(admission.collection_context(), "user_terminal")

    def test_noninteractive_user_collection_is_not_a_user_terminal(self):
        with patch.object(admission.os, "getuid", return_value=1000), \
             patch.object(admission.os, "geteuid", return_value=1000), \
             patch.object(admission.os, "isatty", return_value=False):
            self.assertEqual(admission.collection_context(), "noninteractive_user_session")

    def test_privileged_or_mismatched_uid_keeps_host_unassessed(self):
        for uid, effective_uid in ((0, 0), (1000, 0), (1000, 1001)):
            data = report()
            data["evidence"]["security"].update(uid=uid, effective_uid=effective_uid)
            with self.subTest(uid=uid, effective_uid=effective_uid):
                result = admitted(data)
                self.assertIn(result["host_assessment"], {"UNKNOWN", "NOT TESTED"})

    def test_missing_collector_provenance_is_incomplete(self):
        data = report()
        del data["collector"]
        decision = admitted(data)
        self.assertEqual(decision["sandbox_capability_assessment"], "UNKNOWN")
        self.assertEqual(decision["host_assessment"], "NOT TESTED")

    def test_missing_execution_scope_is_incomplete(self):
        data = report()
        del data["execution_scope"]
        decision = admitted(data)
        self.assertEqual(decision["sandbox_capability_assessment"], "UNKNOWN")
        self.assertEqual(decision["host_assessment"], "NOT TESTED")

    def test_execution_scope_must_match_namespace_observations(self):
        data = report()
        data["execution_scope"]["visibility"] = "NAMESPACE_LIMITED"
        with self.assertRaisesRegex(ValueError, "conflicts"):
            admitted(data)

    def test_different_network_namespace_is_reported_limited(self):
        def readlink(path):
            return {"/proc/self/ns/net": "net:[10]", "/proc/1/ns/net": "net:[11]"}.get(path, path)
        with patch.object(admission.os, "readlink", side_effect=readlink):
            scope = admission.namespace_visibility()
        self.assertEqual(scope["visibility"], "NAMESPACE_LIMITED")

    def test_absent_kvm_is_rejected(self):
        self.assertEqual(admitted(report(kvm="ABSENT"))["status"], "REJECTED")

    def test_known_unsupported_architecture_is_rejected(self):
        data = report()
        data["evidence"]["cpu"]["architecture"] = "aarch64"
        self.assertEqual(admitted(data)["status"], "REJECTED")

    def test_known_missing_hardware_virtualization_flag_is_rejected(self):
        data = report()
        data["evidence"]["cpu"].update(virtualization_flag=None, virtualization_status="ABSENT")
        self.assertEqual(admitted(data)["status"], "REJECTED")

    def test_unavailable_hardware_virtualization_flag_is_unknown(self):
        data = report()
        data["evidence"]["cpu"].update(virtualization_flag=None, virtualization_status="UNKNOWN")
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_missing_or_invalid_cpu_count_is_unknown(self):
        data = report()
        data["evidence"]["cpu"]["logical_cpus"] = 0
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_hidden_network_and_docker_are_unknown_not_absent(self):
        result = admitted(report(routes="UNKNOWN", docker="UNKNOWN"))
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertTrue(any("UNKNOWN" in reason for reason in result["reasons"]))

    def test_missing_disk_measurement_remains_unknown(self):
        data = report(filesystems={"status": "UNKNOWN"})
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_disk_capacity_without_selected_storage_path_is_unknown(self):
        data = report(filesystems={"status": "PRESENT", "stdout":
            "Filesystem Type 1B-blocks Used Available Use% Mounted\n/dev/test ext4 50000000000 1 1000000000 98% /\n"})
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_invalid_selected_storage_path_does_not_assess_wrong_disk(self):
        data = report(filesystems={"status": "PRESENT", "requested_path": "relative/path", "stdout":
            "Filesystem Type 1B-blocks Used Available Use% Mounted\n/dev/test ext4 50000000000 1 1000000000 98% /\n"})
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_malformed_filesystem_field_type_is_rejected_cleanly(self):
        data = report(filesystems={"status": "PRESENT", "stdout": ["not", "text"]})
        with self.assertRaisesRegex(ValueError, "invalid field types"):
            admitted(data)

    def test_import_malformed_report_returns_blocked_without_traceback(self):
        data = report(filesystems={"status": "PRESENT", "stdout": None})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(data))
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(admission.main([
                    "import", str(path), "--expected-host-id", "a" * 32,
                    "--expected-collector-sha256", "b" * 64,
                    "--confirm-host-terminal", "a" * 32,
                ]), 2)
            self.assertIn("BLOCKED: report evidence has invalid field types", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_deeply_nested_json_returns_blocked_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text("[" * 2000 + "0" + "]" * 2000)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(admission.main([
                    "import", str(path), "--expected-host-id", "a" * 32,
                    "--expected-collector-sha256", "b" * 64,
                ]), 2)
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_selected_storage_filesystem_is_used_for_disk_admission(self):
        data = report(filesystems={"status": "PRESENT", "requested_path": "/srv/opla-data",
            "stdout": "Filesystem Type 1B-blocks Used Available Use% Mounted\n/dev/data ext4 50000000000 1 1000000000 98% /srv\n"})
        self.assertEqual(admitted(data)["status"], "REJECTED")

    def test_ambiguous_filesystem_records_remain_unknown(self):
        data = report(filesystems={"status": "PRESENT", "requested_path": "/srv/opla-data",
            "stdout": "Filesystem Type 1B-blocks Used Available Use% Mounted\n/dev/root ext4 50000000000 1 40000000000 1% /\n/dev/data ext4 50000000000 1 1000000000 98% /srv\n"})
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_collect_measures_selected_storage_without_creating_it(self):
        calls = []
        def fake_probe(argv, timeout=4):
            calls.append(argv)
            return {"status": "UNKNOWN", "reason": "fixture"}
        with patch.object(admission, "probe", side_effect=fake_probe), \
             patch.object(admission, "docker_network_inventory", return_value={"status": "UNKNOWN"}), \
             patch.object(admission, "tool_inventory", return_value={}):
            data = admission.collect(Path("/srv/opla-data"))
        self.assertIn(["df", "-PT", "-B1", "--", "/srv/opla-data"], calls)
        self.assertEqual(data["evidence"]["filesystems"]["requested_path"], "/srv/opla-data")

    def test_insufficient_disk_blocks(self):
        data = report(filesystems={"status": "PRESENT", "requested_path": "/var/lib/opla", "stdout":
            "Filesystem Type 1B-blocks Used Available Use% Mounted\n/dev/test ext4 50000000000 1 1000000000 98% /\n"})
        self.assertEqual(admitted(data)["status"], "REJECTED")

    def test_overlapping_route_blocks(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = '[{"dst":"100.64.0.0/10"}]'
        self.assertEqual(admitted(data)["status"], "REJECTED")

    def test_default_route_gateway_inside_lab_pool_blocks(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = json.dumps([
            {"dst": "default", "gateway": "100.64.0.1", "dev": "tun0"}
        ])
        data["evidence"]["network"]["addresses"]["stdout"] = json.dumps([{
            "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24}]
        }])
        decision = admitted(data)
        self.assertEqual(decision["status"], "REJECTED")
        self.assertTrue(any("overlaps built-in OPLA address pool" in reason
                            for reason in decision["reasons"]))

    def test_multipath_default_gateway_inside_lab_pool_blocks(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = json.dumps([
            {"dst": "default", "nexthops": [
                {"gateway": "192.0.2.1", "dev": "wlan0"},
                {"gateway": "100.64.0.1", "dev": "tun0"},
            ]}
        ])
        data["evidence"]["network"]["addresses"]["stdout"] = json.dumps([{
            "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24}]
        }])
        self.assertEqual(admitted(data)["status"], "REJECTED")

    def test_malformed_multipath_gateway_is_unknown(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = json.dumps([
            {"dst": "default", "nexthops": [{"gateway": 100} ]}
        ])
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_malformed_route_gateway_is_unknown_not_admitted(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = json.dumps([
            {"dst": "default", "gateway": "not-an-address", "dev": "tun0"}
        ])
        decision = admitted(data)
        self.assertEqual(decision["status"], "UNKNOWN")
        self.assertTrue(any("malformed route gateway" in reason for reason in decision["reasons"]))

    def test_overlapping_docker_network_blocks(self):
        data = report()
        data["evidence"]["docker"]["networks"]["stdout"] = (
            '[{"Subnet":"100.64.0.0/10"}]')
        self.assertEqual(admitted(data)["status"], "REJECTED")

    def test_partial_docker_endpoint_inventory_keeps_admission_unknown(self):
        data = report()
        data["evidence"]["docker"]["networks"]["host_inventory_complete"] = False
        result = admitted(data)
        self.assertEqual(result["sandbox_capability_assessment"], "UNKNOWN")
        self.assertEqual(result["host_assessment"], "UNKNOWN")
        self.assertTrue(any("all host endpoints" in reason for reason in result["reasons"]))

    def test_expected_host_identity_is_required(self):
        with self.assertRaisesRegex(ValueError, "identity differs"):
            admission.validate(report(), "b" * 32)

    def test_expected_host_identity_format_is_required(self):
        with self.assertRaisesRegex(ValueError, "expected host identity"):
            admission.validate(report(), "A" * 32)

    def test_missing_tools_are_unknown(self):
        data = report()
        data["evidence"]["tools"] = {}
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_user_path_program_is_not_a_trusted_tool(self):
        with patch.object(admission.shutil, "which", return_value="/tmp/qemu-system-x86_64") as which:
            self.assertIsNone(admission.trusted_executable("qemu-system-x86_64"))
            self.assertEqual(which.call_args.kwargs["path"], admission.SYSTEM_PATH)

    def test_trusted_executable_ancestor_walk_terminates(self):
        # Simulate trusted metadata because sandbox system binaries are not
        # root-owned. A bounded call count catches a loop before probe timeout.
        calls = 0
        def root_owned(_path, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 16:
                raise AssertionError("ancestor validation did not advance")
            return SimpleNamespace(st_uid=0, st_mode=0o755)
        with patch.object(admission.shutil, "which", return_value="/usr/bin/python3"):
            with patch.object(admission.Path, "stat", root_owned):
                result = admission.trusted_executable("python3")
        self.assertIsNotNone(result)
        self.assertTrue(result.is_relative_to(Path("/usr/bin")))

    def test_tool_visible_only_outside_trusted_roots_is_unknown(self):
        observed = admission.tool_inventory(
            resolver=lambda name: None,
            ambient_lookup=lambda name: "/opt/local/" + name,
        )["qemu-system-x86_64"]
        self.assertEqual(observed["status"], "UNKNOWN")

    def test_docker_collection_is_bound_to_the_local_unix_socket(self):
        calls = []
        def fake_probe(argv, timeout=4):
            calls.append(argv)
            return {"status": "PRESENT", "stdout": "[]", "stderr": "", "exit_status": 0}
        admission.docker_network_inventory(fake_probe, socket_status="PRESENT")
        docker_calls = [call for call in calls if call[0] == "docker"]
        self.assertTrue(docker_calls)
        for call in docker_calls:
            self.assertEqual(call[1:3], ["--host", "unix:///var/run/docker.sock"])
        inventory = admission.docker_network_inventory(
            lambda argv, timeout=4: {"status": "PRESENT", "stdout": "[]"},
            socket_status="PRESENT")
        self.assertFalse(inventory["host_inventory_complete"])

    def test_absent_local_docker_socket_keeps_network_inventory_unknown(self):
        inventory = admission.docker_network_inventory(socket_status="ABSENT")
        self.assertEqual(inventory["status"], "UNKNOWN")
        self.assertEqual(inventory["endpoint_status"], "ABSENT")
        data = report(docker="ABSENT")
        decision = admitted(data)
        self.assertEqual(decision["status"], "UNKNOWN")
        self.assertTrue(any("Docker inventory" in reason
                            for reason in decision["reasons"]))

    def test_unknown_local_docker_socket_keeps_network_assessment_unknown(self):
        data = report(docker="UNKNOWN")
        decision = admitted(data)
        self.assertEqual(decision["status"], "UNKNOWN")
        self.assertTrue(any("Docker inventory" in reason
                            for reason in decision["reasons"]))

    def test_non_socket_docker_endpoint_is_not_claimed_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            endpoint = Path(tmp) / "docker.sock"
            endpoint.write_text("not a socket")
            self.assertEqual(admission.local_docker_socket_status(endpoint), "UNKNOWN")

    def test_symlinked_docker_endpoint_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_text("not a socket")
            endpoint = Path(tmp) / "docker.sock"
            endpoint.symlink_to(target)
            self.assertEqual(admission.local_docker_socket_status(endpoint), "UNKNOWN")

    def test_probe_uses_scrubbed_environment(self):
        class Process:
            pid = 1
            def wait(self, timeout=None):
                return 0
        with patch.object(admission, "trusted_executable", return_value=Path("/usr/bin/true")), \
             patch.object(admission.subprocess, "Popen", return_value=Process()) as popen:
            self.assertEqual(admission.probe(["ip", "-j", "address"])["status"], "PRESENT")
        self.assertEqual(popen.call_args.kwargs["env"], admission.PROBE_ENV)

    def test_probe_wait_oserror_kills_and_reaps_owned_process(self):
        class Process:
            pid = 12345
            def wait(self, timeout=None):
                raise OSError("wait interrupted")
        process = Process()
        with patch.object(admission, "trusted_executable", return_value=Path("/usr/bin/true")), \
             patch.object(admission.subprocess, "Popen", return_value=process), \
             patch.object(admission.os, "killpg") as killpg:
            result = admission.probe(["ip", "-j", "address"])
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["reason"], "OSError")
        self.assertEqual(result["cleanup_error"], "wait: OSError")
        killpg.assert_called_once_with(process.pid, admission.signal.SIGKILL)

    def test_empty_process_inventory_is_unknown(self):
        data = report()
        data["evidence"]["processes"]["stdout"] = ""
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_empty_route_inventory_is_unknown(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = "[]"
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_whitespace_empty_route_inventory_is_unknown(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = "[ ]"
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_malformed_route_cidr_is_unknown_not_admitted(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = '[{"dst":"not-a-cidr"}]'
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_malformed_address_inventory_is_unknown_not_admitted(self):
        data = report()
        data["evidence"]["network"]["addresses"]["stdout"] = '[{"addr_info":"malformed"}]'
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_malformed_docker_subnet_is_unknown_not_admitted(self):
        data = report()
        data["evidence"]["docker"]["networks"]["stdout"] = '[{"Subnet":"bad"}]'
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_duplicate_route_keys_cannot_hide_conflicting_subnet(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = (
            '[{"dst":"100.64.0.0/10","dst":"192.0.2.0/24"}]')
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_duplicate_docker_keys_cannot_hide_conflicting_subnet(self):
        data = report()
        data["evidence"]["docker"]["networks"]["stdout"] = (
            '[{"Subnet":"100.64.0.0/10","Subnet":"192.0.2.0/24"}]')
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_nonfinite_inner_route_json_is_unknown(self):
        data = report()
        data["evidence"]["network"]["routes"]["stdout"] = (
            '[{"dst":"192.0.2.0/24","metric":NaN}]')
        self.assertEqual(admitted(data)["status"], "UNKNOWN")

    def test_all_interface_addresses_are_checked_for_overlap(self):
        data = report()
        data["evidence"]["network"]["addresses"]["stdout"] = json.dumps([{
            "addr_info": [
                {"family": "inet", "local": "100.64.1.3", "prefixlen": 24},
                {"family": "inet", "local": "192.0.2.1", "prefixlen": 24},
            ]
        }])
        self.assertEqual(admitted(data)["status"], "REJECTED")

    def test_incomplete_report_preserves_unknown_measurements(self):
        data = report()
        del data["evidence"]["network"]
        decision = admitted(data)
        self.assertEqual(decision["sandbox_capability_assessment"], "UNKNOWN")
        self.assertIn(decision["host_assessment"], {"UNKNOWN", "NOT TESTED"})

    def test_missing_listener_inventory_is_unknown(self):
        data = report()
        del data["evidence"]["listeners"]
        decision = admitted(data)
        self.assertEqual(decision["sandbox_capability_assessment"], "UNKNOWN")
        self.assertIn(decision["host_assessment"], {"UNKNOWN", "NOT TESTED"})

    def test_missing_service_inventory_is_unknown(self):
        data = report()
        del data["evidence"]["services"]
        decision = admitted(data)
        self.assertEqual(decision["sandbox_capability_assessment"], "UNKNOWN")

    def test_missing_machine_identity_is_not_treated_as_host_capability_failure(self):
        data = report()
        data["host"]["machine_id"] = None
        decision = admitted(data)
        self.assertEqual(decision["status"], "NOT TESTED")
        self.assertTrue(any("machine identity missing" in reason for reason in decision["reasons"]))

    def test_missing_timestamp_is_not_treated_as_stale_or_host_failure(self):
        data = report()
        del data["collected_at"]
        decision = admitted(data)
        self.assertEqual(decision["status"], "NOT TESTED")
        self.assertTrue(any("timestamp missing" in reason for reason in decision["reasons"]))

    def test_old_report_is_rejected(self):
        data = report()
        data["collected_at"] = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        with self.assertRaisesRegex(ValueError, "older"):
            admitted(data)

    def test_import_reads_json_without_host_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(report()))
            raw = admission.safe_read(path)
            self.assertEqual(admitted(json.loads(raw))["status"], "CONDITIONALLY ADMITTED")

    def test_import_rejects_duplicate_json_keys_without_running_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            payload = json.dumps(report())[:-1] + ', "kind": "opla_host_admission"}'
            path.write_text(payload)
            original_probe = admission.probe
            admission.probe = lambda *args, **kwargs: self.fail("import must not probe the host")
            try:
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(admission.main([
                        "import", str(path), "--expected-host-id", "a" * 32,
                        "--expected-collector-sha256", "b" * 64,
                    ]), 2)
                self.assertIn("duplicate JSON key", stderr.getvalue())
            finally:
                admission.probe = original_probe

    def test_safe_read_rejects_symlinked_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target.json"
            target.write_text(json.dumps(report()))
            alias = Path(tmp) / "alias.json"
            alias.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlinks"):
                admission.safe_read(alias)

    def test_safe_read_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "report.pipe"
            admission.os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular file"):
                admission.safe_read(fifo)

    def test_safe_read_rejects_symlinked_parent_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            real.mkdir()
            (real / "report.json").write_text(json.dumps(report()))
            alias = Path(tmp) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlinks"):
                admission.safe_read(alias / "report.json")

    def test_import_can_persist_hash_bound_decision_without_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.json"
            decision = Path(tmp) / "decision.json"
            source.write_text(json.dumps(report()))
            original_probe = admission.probe
            admission.probe = lambda *args, **kwargs: self.fail("import must not probe the host")
            try:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(admission.main([
                        "import", str(source), "--expected-host-id", "a" * 32,
                        "--expected-collector-sha256", "b" * 64,
                        "--confirm-host-terminal", "a" * 32,
                        "--output", str(decision),
                    ]), 0)
            finally:
                admission.probe = original_probe
            saved = json.loads(decision.read_text())
            self.assertEqual(saved["status"], "CONDITIONALLY ADMITTED")
            self.assertEqual(saved["source_sha256"], __import__("hashlib").sha256(source.read_bytes()).hexdigest())
            self.assertEqual(saved["provenance"]["collector_fingerprint"], "MATCHED_INDEPENDENT_PIN")

    def test_decision_output_rejects_existing_or_symlinked_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "decision.json"
            existing.write_text("existing")
            with self.assertRaises(FileExistsError):
                admission.write_new(existing, b"replacement")
            target = Path(tmp) / "target.json"
            target.write_text("target")
            alias = Path(tmp) / "alias.json"
            alias.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlinks"):
                admission.write_new(alias, b"replacement")

    def test_decision_output_rejects_symlinked_parent_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            real.mkdir()
            alias = Path(tmp) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlinks"):
                admission.write_new(alias / "decision.json", b"decision")
            self.assertFalse((real / "decision.json").exists())

    def test_output_fsync_failure_preserves_partial_output_for_reconciliation(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "decision.json"
            with patch.object(admission.os, "fsync", side_effect=OSError("disk failure")):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    admission.write_new(destination, b"evidence")
            self.assertEqual(destination.read_bytes(), b"evidence")

    def test_parent_fsync_failure_preserves_ambiguous_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "decision.json"
            with patch.object(admission.os, "fsync", side_effect=[None, OSError("directory failure")]):
                with self.assertRaisesRegex(OSError, "reconcile manually"):
                    admission.write_new(destination, b"evidence")
            self.assertEqual(destination.read_bytes(), b"evidence")

    def test_failed_output_never_uses_path_unlink_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "decision.json"
            with patch.object(admission.os, "fsync", side_effect=OSError("disk failure")), \
                 patch.object(admission.os, "unlink") as unlink:
                with self.assertRaisesRegex(OSError, "disk failure"):
                    admission.write_new(destination, b"evidence")
            unlink.assert_not_called()
            destination.unlink()


if __name__ == "__main__":
    unittest.main()
