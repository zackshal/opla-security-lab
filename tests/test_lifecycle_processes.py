"""Existing process identity verification against a synthetic proc tree."""

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("process_recovery", ROOT / "bin/opla-active-creation-recover.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class ProcessEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.lab = "lab-fixture123"
        self.services = {}
        for index, role in enumerate(("attacker", "victim", "client", "dhcp"), 100):
            unit = f"qemu-{self.lab}-{role}.service" if role != "dhcp" else f"dhcp-{self.lab}.service"
            binary = "qemu-system-x86_64" if role != "dhcp" else "dnsmasq"
            marker = (f"file={self.root / self.lab / role / 'disk.qcow2'},if=virtio"
                      if role != "dhcp" else f"--conf-file={self.root / self.lab / 'dnsmasq.conf'}")
            self.services[unit] = f"ActiveState=active\nMainPID={index}\n"
            self.process(index, binary, marker, unit)

    def process(self, pid, binary, marker, unit):
        path = self.proc / str(pid)
        path.mkdir()
        (path / "cmdline").write_bytes(binary.encode() + b"\0" + marker.encode() + b"\0")
        (path / "exe").symlink_to("/usr/bin/" + binary)
        (path / "cgroup").write_text("0::/system.slice/" + unit + "\n")
        (path / "fd").mkdir()
        return path

    def runner(self, argv):
        return subprocess.CompletedProcess(argv, 0, self.services[argv[2]], "")

    def evidence(self):
        return recovery.process_evidence(self.root, self.lab, runner=self.runner, proc_root=self.proc)

    def test_exact_process_identities_are_observed_without_live_proc(self):
        self.assertEqual(set(self.evidence()), {100, 101, 102, 103})

    def test_disk_path_prefix_is_not_an_identity(self):
        path = self.proc / "100" / "cmdline"
        path.write_bytes(path.read_bytes().replace(b"disk.qcow2,", b"disk.qcow2-foreign,"))
        with self.assertRaisesRegex(recovery.Blocked, "identity mismatch"):
            self.evidence()

    def test_cgroup_unit_suffix_is_not_an_identity(self):
        path = self.proc / "100" / "cgroup"
        path.write_text(path.read_text().replace(".service", ".service-foreign"))
        with self.assertRaisesRegex(recovery.Blocked, "identity mismatch"):
            self.evidence()

    def test_untracked_process_reference_blocks(self):
        self.process(999, "reader", str(self.root / self.lab / "victim/disk.qcow2"), "other.service")
        with self.assertRaisesRegex(recovery.Blocked, "untracked process"):
            self.evidence()

    def test_foreign_executable_blocks(self):
        path = self.proc / "100" / "exe"
        path.unlink()
        path.symlink_to("/usr/bin/foreign")
        with self.assertRaisesRegex(recovery.Blocked, "identity mismatch"):
            self.evidence()

    def test_transitioning_service_blocks(self):
        unit = next(iter(self.services))
        self.services[unit] = "ActiveState=activating\nMainPID=100\n"
        with self.assertRaisesRegex(recovery.Blocked, "transitioning"):
            self.evidence()

    def test_missing_proc_evidence_is_not_success(self):
        (self.proc / "100" / "cmdline").unlink()
        with self.assertRaises(FileNotFoundError):
            self.evidence()

    def test_registry_composition_preserves_process_evidence_without_ownership_claim(self):
        import asyncio
        from test_lifecycle_operations import Backend, operations
        backend = Backend()
        backend.actual = self.lab
        backend.completed.add("create")
        operation = operations.OperationsAdapter(backend)
        operation.actual_lab_id = self.lab
        adapter = operations.RegistryAdapter(
            operation, root=self.root,
            inspector=lambda kind, _: ("active" if kind.endswith("_unit") else "present", "mock"),
            process_inspector=lambda root, lab: recovery.process_evidence(
                root, lab, runner=self.runner, proc_root=self.proc))
        path = self.root / self.lab
        path.mkdir()
        state = path / "state.env"
        state.write_text(
            f"LAB_ID={self.lab}\nBRIDGE=br-op7\nSUBNET=100.64.0.0/29\n"
            "MGMT_BRIDGE=br-op8\nMGMT_SUBNET=100.64.0.8/29\n"
            "MGMT_GW=100.64.0.9\nATTACKER_MGMT_IP=100.64.0.10\n"
            "VICTIM_MGMT_IP=100.64.0.11\nCLIENT_MGMT_IP=100.64.0.12\n"
        )
        state.chmod(0o600)
        adapter.verifier.reg.persist(self.root, self.lab, "ready")
        observed = asyncio.run(adapter.probe("create", "lab-correlation123"))
        self.assertEqual(set(observed["process_observations"]), {100, 101, 102, 103})
        self.assertFalse(observed["ownership"])


if __name__ == "__main__":
    unittest.main()
