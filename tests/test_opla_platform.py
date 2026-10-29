import importlib.util
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("opla_platform", ROOT / "bin/opla-platform.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PlatformDetectionTests(TestCase):

    @staticmethod
    def trusted_tool(name):
        return Path("/usr/bin") / name

    @staticmethod
    def present_kvm(_path):
        return {"status": "PRESENT", "read_write_access": True, "reason": "fixture character device"}
    def test_compatibility_documents_keep_runtime_claims_conservative(self):
        for name in (
            "platform-compatibility.md",
            "multiarch-support.md",
            "platform-backend-architecture.md",
        ):
            text = (ROOT / "docs" / name).read_text(encoding="utf-8")
            self.assertIn("NOT TESTED", text)
            self.assertIn("BLOCKED", text)
        matrix = (ROOT / "docs" / "platform-compatibility.md").read_text(encoding="utf-8")
        self.assertIn("macOS", matrix)
        self.assertIn("Windows", matrix)
        self.assertIn("ARM64", (ROOT / "docs" / "multiarch-support.md").read_text(encoding="utf-8"))

    def test_architecture_aliases_are_normalized_without_support_claim(self):
        self.assertEqual(MODULE.normalize_arch("x86_64"), "x86_64")
        self.assertEqual(MODULE.normalize_arch("aarch64"), "arm64")
        self.assertEqual(MODULE.normalize_arch("riscv64"), "riscv64")
        self.assertEqual(MODULE.normalize_arch("mystery"), "mystery")

    def test_memory_admission_threshold_matches_real_three_vm_launch_plan(self):
        launcher = (ROOT / "bin/create-lab.sh").read_text(encoding="utf-8")
        platform_source = (ROOT / "bin/opla-platform.py").read_text(encoding="utf-8")
        admission_source = (ROOT / "bin/opla-host-admission.py").read_text(encoding="utf-8")
        host_spec = (ROOT / "docs/test-host-spec.md").read_text(encoding="utf-8")

        allocations = {
            role: int(memory)
            for role, memory in re.findall(
                r"^create_vm (attacker|victim|client) (\d+) \d+",
                launcher, flags=re.MULTILINE)
        }
        self.assertEqual(allocations, {"attacker": 1024, "victim": 2048, "client": 512})
        reserve_match = re.search(r"# Reserve another (\d+) MiB", launcher)
        self.assertIsNotNone(reserve_match)
        required_kib = (sum(allocations.values()) + int(reserve_match.group(1))) * 1024
        platform_match = re.search(r"MIN_MEM_AVAILABLE_KIB = (\d+) \* 1024", platform_source)
        admission_match = re.search(r"available < (\d+) \* 1024", admission_source)
        self.assertIsNotNone(platform_match)
        self.assertIsNotNone(admission_match)
        self.assertEqual(required_kib, int(platform_match.group(1)) * 1024)
        self.assertEqual(required_kib, int(admission_match.group(1)) * 1024)
        self.assertIn(f"at least {required_kib // 1024} MiB `MemAvailable`", host_spec)

    def test_os_release_is_read_as_data(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write('NAME="Debian GNU/Linux"\nID=debian\nVERSION_ID="13"\n')
            handle.flush()
            data = MODULE.read_os_release(Path(handle.name))
        self.assertEqual(data["ID"], "debian")
        self.assertEqual(data["VERSION_ID"], "13")

    def test_malformed_or_duplicate_os_release_identity_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "os-release"
            path.write_text('ID="debian\nVERSION_ID=13\n', encoding="utf-8")
            self.assertEqual(MODULE.read_os_release(path), {"VERSION_ID": "13"})
            path.write_text("ID=debian\nID=ubuntu\nVERSION_ID=13\n", encoding="utf-8")
            self.assertEqual(MODULE.read_os_release(path), {"VERSION_ID": "13"})
            path.write_text("ID=debian\nVERSION_ID=12\nVERSION_ID=13\n", encoding="utf-8")
            self.assertEqual(MODULE.read_os_release(path), {"ID": "debian"})
            path.write_text('ID=debian\nVERSION_ID="13\n', encoding="utf-8")
            self.assertEqual(MODULE.read_os_release(path), {"ID": "debian"})

    def test_memory_and_storage_facts_are_observed_without_admission_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meminfo = root / "meminfo"
            meminfo.write_text("MemTotal:       9999 kB\nMemAvailable:   6000000 kB\nSwapTotal: 0 kB\n", encoding="utf-8")
            memory = MODULE.read_meminfo(meminfo)
            storage = MODULE.storage_facts(root / "missing" / "lab")
        self.assertEqual(memory["MemAvailable"], 6000000)
        self.assertNotIn("SwapFree", memory)
        self.assertTrue(storage["available"])
        self.assertIn("no free-disk admission threshold", storage["reason"])

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.os, "access", return_value=True)
    def test_low_available_memory_blocks_vm_preflight(self, _access, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            meminfo = root / "meminfo"
            meminfo.write_text("MemAvailable: 1 kB\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=root / "missing-os-release", dev_kvm=kvm,
                meminfo=meminfo, storage_root=root, tool_resolver=self.trusted_tool,
                kvm_evidence_resolver=self.present_kvm,
            )
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "BLOCKED")
        self.assertFalse(result["resources"]["memory"]["meets_create_preflight"])
        self.assertIn("MemAvailable", result["capabilities"]["vm_hosting"]["reason"])

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.os, "access", return_value=True)
    def test_missing_memavailable_is_unknown_not_technical_failure(self, _access, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            meminfo = root / "meminfo"
            meminfo.write_text("MemTotal: 999 kB\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=root / "missing-os-release", dev_kvm=kvm,
                meminfo=meminfo, storage_root=root, tool_resolver=self.trusted_tool,
                kvm_evidence_resolver=self.present_kvm,
            )
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "UNKNOWN")
        self.assertIsNone(result["resources"]["memory"]["mem_available_kib"])
        self.assertIn("MemAvailable unavailable", result["capabilities"]["vm_hosting"]["reason"])

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.os, "access", return_value=True)
    def test_exact_memory_threshold_is_feasible_but_not_runtime_tested(self, _access, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            meminfo = root / "meminfo"
            meminfo.write_text(f"MemAvailable: {MODULE.MIN_MEM_AVAILABLE_KIB} kB\n", encoding="utf-8")
            os_release = root / "os-release"
            os_release.write_text("ID=debian\nVERSION_ID=13\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=os_release, dev_kvm=kvm,
                meminfo=meminfo, storage_root=root, tool_resolver=self.trusted_tool,
                kvm_evidence_resolver=self.present_kvm,
            )
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "FEASIBLE")
        self.assertEqual(result["capabilities"]["vm_hosting"]["status"], "BLOCKED")
        self.assertTrue(result["resources"]["memory"]["meets_create_preflight"])

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="aarch64")
    def test_host_identity_is_observable(self, _machine, _system):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("ID=debian\nVERSION_ID=13\n")
            handle.flush()
            result = MODULE.detect_host(os_release=Path(handle.name))
        self.assertEqual(result["system"], "linux")
        self.assertEqual(result["machine"], "arm64")
        self.assertEqual(result["distribution"], "debian")

    @patch.object(MODULE.py_platform, "system", return_value="Darwin")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    def test_non_linux_host_fails_closed_for_vm_backend(self, _machine, _system):
        result = MODULE.inspect_capabilities(
            os_release=Path("/nonexistent/opla-os-release"),
            dev_kvm=ROOT / "tests" / "fixtures" / "missing-kvm",
            tool_resolver=self.trusted_tool,
        )
        self.assertEqual(result["capabilities"]["control_plane"]["status"], "FEASIBLE")
        self.assertEqual(result["capabilities"]["vm_hosting"]["status"], "BLOCKED")
        self.assertEqual(result["capabilities"]["guest_runtime"]["status"], "BLOCKED")
        self.assertEqual(result["capabilities"]["guest_runtime"]["preflight_status"], "UNKNOWN")
        self.assertFalse(result["execution"]["performed"])

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    def test_missing_kvm_fails_closed_even_when_tools_exist(self, _machine, _system):
        result = MODULE.inspect_capabilities(
            os_release=Path("/nonexistent/opla-os-release"),
            dev_kvm=ROOT / "tests" / "fixtures" / "missing-kvm",
            tool_resolver=self.trusted_tool,
        )
        self.assertEqual(result["capabilities"]["vm_hosting"]["status"], "BLOCKED")
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "BLOCKED")
        self.assertIn("/dev/kvm absent", result["capabilities"]["vm_hosting"]["reason"])

    def test_kvm_metadata_denial_is_unknown_not_absent(self):
        with patch.object(MODULE.Path, "stat", side_effect=PermissionError("hidden by sandbox")):
            evidence = MODULE.kvm_device_evidence(Path("/dev/kvm"))
        self.assertEqual(evidence["status"], "UNKNOWN")
        self.assertIsNone(evidence["read_write_access"])

    def test_kvm_requires_character_device_not_file_or_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            regular = root / "not-kvm"
            regular.touch()
            directory = root / "directory"
            directory.mkdir()
            alias = root / "alias"
            alias.symlink_to(regular)
            for candidate in (regular, directory, alias):
                with self.subTest(candidate=candidate.name):
                    evidence = MODULE.kvm_device_evidence(candidate)
                    self.assertEqual(evidence["status"], "INVALID")
                    self.assertIn("not a character device", evidence["reason"])

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.Path, "stat", return_value=SimpleNamespace(
        st_mode=MODULE.stat.S_IFCHR | 0o600))
    @patch.object(MODULE.os, "access", return_value=False)
    def test_current_user_kvm_access_denial_is_unknown_not_host_rejection(
            self, _access, _stat, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            (root / "meminfo").write_text(
                f"MemAvailable: {MODULE.MIN_MEM_AVAILABLE_KIB} kB\n", encoding="utf-8")
            (root / "os-release").write_text("ID=debian\nVERSION_ID=13\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=root / "os-release", dev_kvm=kvm,
                meminfo=root / "meminfo", storage_root=root,
                required_tools=(),
                kvm_evidence_resolver=lambda _path: {
                    "status": "INACCESSIBLE", "read_write_access": False,
                    "reason": "not readable and writable by the current process identity"},
            )
        self.assertEqual(result["kvm"]["status"], "INACCESSIBLE")
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "UNKNOWN")
        self.assertEqual(result["assessment_scope"],
                         "current process-visible environment; physical host status NOT TESTED")

    def test_cli_require_returns_nonzero_for_unavailable_backend(self):
        with patch.object(MODULE, "inspect_capabilities", return_value={
            "host": {"system": "linux", "machine": "x86_64", "distribution": "debian"},
            "capabilities": {
                "control_plane": {"status": "FEASIBLE", "reason": "fixture"},
                "vm_hosting": {"status": "BLOCKED", "preflight_status": "FEASIBLE", "reason": "fixture"},
                "guest_runtime": {"status": "BLOCKED", "reason": "fixture"},
            },
            "execution": {"performed": False, "live_status": "NOT TESTED", "mutated_host": False},
        }):
            self.assertEqual(MODULE.main(["--require", "vm-hosting"]), 2)

    def test_linux_host_cannot_establish_guest_runtime_preflight(self):
        with patch.object(MODULE.py_platform, "system", return_value="Linux"), \
             patch.object(MODULE.py_platform, "machine", return_value="x86_64"):
            result = MODULE.inspect_capabilities(
                os_release=Path("/nonexistent/opla-os-release"),
                dev_kvm=ROOT / "tests" / "fixtures" / "missing-kvm",
                tool_resolver=self.trusted_tool,
            )
        self.assertEqual(result["capabilities"]["guest_runtime"]["preflight_status"], "UNKNOWN")
        self.assertEqual(result["capabilities"]["guest_runtime"]["status"], "BLOCKED")

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.os, "access", return_value=True)
    def test_unvalidated_linux_distribution_is_unknown_not_feasible(self, _access, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            meminfo = root / "meminfo"
            meminfo.write_text(f"MemAvailable: {MODULE.MIN_MEM_AVAILABLE_KIB} kB\n", encoding="utf-8")
            os_release = root / "os-release"
            os_release.write_text("ID=ubuntu\nVERSION_ID=24.04\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=os_release, dev_kvm=kvm, meminfo=meminfo,
                storage_root=root, tool_resolver=self.trusted_tool,
                kvm_evidence_resolver=self.present_kvm,
            )
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "UNKNOWN")
        self.assertIn("no built-in host profile", result["capabilities"]["vm_hosting"]["reason"])
        self.assertEqual(result["capabilities"]["vm_hosting"]["status"], "BLOCKED")

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.os, "access", return_value=True)
    def test_missing_distribution_identity_is_unknown_not_feasible(self, _access, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            meminfo = root / "meminfo"
            meminfo.write_text(f"MemAvailable: {MODULE.MIN_MEM_AVAILABLE_KIB} kB\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=root / "missing-os-release", dev_kvm=kvm, meminfo=meminfo,
                storage_root=root, tool_resolver=self.trusted_tool,
                kvm_evidence_resolver=self.present_kvm,
            )
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "UNKNOWN")
        self.assertIn("no built-in host profile", result["capabilities"]["vm_hosting"]["reason"])

    def test_untrusted_path_cannot_satisfy_required_tool(self):
        with patch.object(MODULE.shutil, "which", return_value="/tmp/qemu-system-x86_64") as which:
            self.assertIsNone(MODULE.trusted_tool_path("qemu-system-x86_64"))
            self.assertEqual(which.call_args.kwargs["path"], MODULE.SYSTEM_PATH)

    def test_writable_candidate_inside_system_root_is_not_trusted(self):
        writable = SimpleNamespace(st_uid=0, st_mode=0o100775)
        with patch.object(MODULE.shutil, "which", return_value="/usr/bin/qemu-system-x86_64"), \
             patch.object(MODULE.Path, "stat", return_value=writable):
            self.assertIsNone(MODULE.trusted_tool_path("qemu-system-x86_64"))

    def test_tool_metadata_failure_is_not_trusted(self):
        with patch.object(MODULE.shutil, "which", return_value="/usr/bin/qemu-system-x86_64"), \
             patch.object(MODULE.Path, "stat", side_effect=OSError("metadata unavailable")):
            self.assertIsNone(MODULE.trusted_tool_path("qemu-system-x86_64"))
            evidence = MODULE.trusted_tool_evidence("qemu-system-x86_64")
        self.assertEqual(evidence["status"], "UNKNOWN")

    def test_absent_tool_is_distinguished_from_unreadable_metadata(self):
        with patch.object(MODULE.shutil, "which", return_value=None):
            evidence = MODULE.trusted_tool_evidence("qemu-system-x86_64")
        self.assertEqual(evidence["status"], "ABSENT")

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.os, "access", return_value=True)
    def test_unknown_tool_evidence_yields_unknown_preflight(self, _access, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            (root / "meminfo").write_text(
                f"MemAvailable: {MODULE.MIN_MEM_AVAILABLE_KIB} kB\n", encoding="utf-8")
            (root / "os-release").write_text("ID=debian\nVERSION_ID=13\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=root / "os-release", dev_kvm=kvm,
                meminfo=root / "meminfo", storage_root=root,
                required_tools=("qemu-system-x86_64",),
                tool_evidence_resolver=lambda _name: {
                    "status": "UNKNOWN", "path": None, "reason": "sandbox metadata denied"},
                kvm_evidence_resolver=self.present_kvm,
            )
        self.assertEqual(result["tools"]["qemu-system-x86_64"]["status"], "UNKNOWN")
        self.assertIsNone(result["tools"]["qemu-system-x86_64"]["available"])
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "UNKNOWN")

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    def test_unknown_kvm_visibility_does_not_serialize_as_absent(self, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "meminfo").write_text(
                f"MemAvailable: {MODULE.MIN_MEM_AVAILABLE_KIB} kB\n", encoding="utf-8")
            (root / "os-release").write_text("ID=debian\nVERSION_ID=13\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=root / "os-release", dev_kvm=root / "kvm",
                meminfo=root / "meminfo", storage_root=root, required_tools=(),
                kvm_evidence_resolver=lambda _path: {
                    "status": "UNKNOWN", "read_write_access": None,
                    "reason": "sandbox metadata denied"},
            )
        self.assertEqual(result["kvm"]["status"], "UNKNOWN")
        self.assertIsNone(result["kvm"]["present"])
        self.assertIsNone(result["kvm"]["read_write_access"])
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "UNKNOWN")

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.os, "access", return_value=True)
    def test_known_absent_tool_blocks_preflight(self, _access, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            (root / "meminfo").write_text(
                f"MemAvailable: {MODULE.MIN_MEM_AVAILABLE_KIB} kB\n", encoding="utf-8")
            (root / "os-release").write_text("ID=debian\nVERSION_ID=13\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=root / "os-release", dev_kvm=kvm,
                meminfo=root / "meminfo", storage_root=root,
                required_tools=("qemu-system-x86_64",),
                tool_evidence_resolver=lambda _name: {
                    "status": "ABSENT", "path": None, "reason": "not installed"},
                kvm_evidence_resolver=self.present_kvm,
            )
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "BLOCKED")
        self.assertIn("absent", result["capabilities"]["vm_hosting"]["reason"])

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="aarch64")
    @patch.object(MODULE.os, "access", return_value=True)
    def test_known_unsupported_architecture_blocks_vm_preflight(self, _access, _machine, _system):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kvm = root / "kvm"
            kvm.touch()
            meminfo = root / "meminfo"
            meminfo.write_text(f"MemAvailable: {MODULE.MIN_MEM_AVAILABLE_KIB} kB\n", encoding="utf-8")
            result = MODULE.inspect_capabilities(
                os_release=root / "missing-os-release", dev_kvm=kvm,
                meminfo=meminfo, storage_root=root, tool_resolver=self.trusted_tool,
                kvm_evidence_resolver=self.present_kvm,
            )
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "BLOCKED")
        self.assertIn("requires x86_64", result["capabilities"]["vm_hosting"]["reason"])

