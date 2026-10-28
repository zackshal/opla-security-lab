import importlib.util
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("opla_platform", ROOT / "bin/opla-platform.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PlatformDetectionTests(TestCase):
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

    def test_os_release_is_read_as_data(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write('NAME="Debian GNU/Linux"\nID=debian\nVERSION_ID="13"\n')
            handle.flush()
            data = MODULE.read_os_release(Path(handle.name))
        self.assertEqual(data["ID"], "debian")
        self.assertEqual(data["VERSION_ID"], "13")

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
    @patch.object(MODULE.shutil, "which", return_value="/bin/tool")
    def test_non_linux_host_fails_closed_for_vm_backend(self, _which, _machine, _system):
        result = MODULE.inspect_capabilities(
            os_release=Path("/nonexistent/opla-os-release"),
            dev_kvm=ROOT / "tests" / "fixtures" / "missing-kvm",
        )
        self.assertEqual(result["capabilities"]["control_plane"]["status"], "FEASIBLE")
        self.assertEqual(result["capabilities"]["vm_hosting"]["status"], "BLOCKED")
        self.assertEqual(result["capabilities"]["guest_runtime"]["status"], "BLOCKED")
        self.assertFalse(result["execution"]["performed"])

    @patch.object(MODULE.py_platform, "system", return_value="Linux")
    @patch.object(MODULE.py_platform, "machine", return_value="x86_64")
    @patch.object(MODULE.shutil, "which", return_value="/bin/tool")
    def test_missing_kvm_fails_closed_even_when_tools_exist(self, _which, _machine, _system):
        result = MODULE.inspect_capabilities(
            os_release=Path("/nonexistent/opla-os-release"),
            dev_kvm=ROOT / "tests" / "fixtures" / "missing-kvm",
        )
        self.assertEqual(result["capabilities"]["vm_hosting"]["status"], "BLOCKED")
        self.assertEqual(result["capabilities"]["vm_hosting"]["preflight_status"], "BLOCKED")
        self.assertIn("/dev/kvm absent", result["capabilities"]["vm_hosting"]["reason"])

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

    def test_linux_preflight_never_admits_untested_guest_runtime(self):
        with patch.object(MODULE.py_platform, "system", return_value="Linux"), \
             patch.object(MODULE.py_platform, "machine", return_value="x86_64"), \
             patch.object(MODULE.shutil, "which", return_value="/bin/tool"):
            result = MODULE.inspect_capabilities(
                os_release=Path("/nonexistent/opla-os-release"),
                dev_kvm=ROOT / "tests" / "fixtures" / "missing-kvm",
            )
        self.assertEqual(result["capabilities"]["guest_runtime"]["preflight_status"], "FEASIBLE")
        self.assertEqual(result["capabilities"]["guest_runtime"]["status"], "BLOCKED")

