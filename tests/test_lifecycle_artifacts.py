"""Parser-backed lifecycle acceptance, using only synthetic local artifacts."""

import hashlib
import asyncio
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import yaml  # noqa: F401
except ImportError:
    raise unittest.SkipTest("PyYAML unavailable; lifecycle artifact parser tests skipped")

from tests.test_lifecycle_acceptance import FakeAdapter, orchestrator

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lab_artifacts", ROOT / "bin/opla-lab-artifacts.py")
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class ArtifactAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.commands = []
        self.operations = FakeAdapter()
        self.experiment = self.root / "scenario-syn-OFFLINE"
        self.experiment.mkdir()
        self.image_dir = self.root / "images"
        self.image_dir.mkdir()
        for role, (name, _) in artifacts.images.ROLE_IMAGES.items():
            data = ("synthetic image " + role).encode()
            (self.image_dir / name).write_bytes(data)
            (self.image_dir / (name + ".sha256")).write_text(
                hashlib.sha256(data).hexdigest() + "  " + name + "\n")
            (self.image_dir / (name + ".role")).write_text(role)
            (self.image_dir / (name + ".packages")).write_text(
                "\n".join(sorted(artifacts.images.ROLE_PACKAGES[role])) + "\n")
        self.write("interval.json", {"schema_version": 1,
                   "start": "2026-10-27T13:00:00Z", "end": "2026-10-27T13:00:10Z",
                   "source_ip": "100.64.0.2", "target_ip": "100.64.0.3"})
        self.write("before.json", {"loaded": 1, "syn": 100, "drop": 10, "pass": 90})
        self.write("after.json", {"loaded": 1, "syn": 150, "drop": 50, "pass": 100})
        self.write("eve.json", {"event_type": "alert", "timestamp": "2026-10-27T13:00:05Z",
                   "src_ip": "100.64.0.2", "dest_ip": "100.64.0.3",
                   "proto": "TCP", "alert": {"signature_id": 100001, "signature": "fixture"}})
        self.write("events.jsonl", {"timestamp": 1793106005, "source_ip": "100.64.0.2",
                   "destination_ip": "100.64.0.3", "event": "tcp_port_scan_suspected"})
        fingerprint = {"loaded": 1, "program_id": 7, "program_tag": "fixture",
                       "attachment_mode": "native", "loaded_object_identity_verified": True,
                       "load_receipt": {"object_sha256": "a" * 64,
                                        "build_manifest_sha256": "b" * 64}}
        for suffix in ("before", "after"):
            self.write("fingerprint-" + suffix + ".json", fingerprint)
        for kind in ("suricata", "scan"):
            self.write(kind + "-evidence-meta.json", {"status": "captured", "coverage": "unverified"})
        self.adapter = artifacts.ArtifactAdapter(
            self.operations, image_directory=self.image_dir, image_runner=self.runner,
            scenario="syn-scan-baseline", experiment=self.experiment)

    def write(self, name, obj):
        (self.experiment / name).write_text(json.dumps(obj) + "\n")

    def runner(self, argv, **kwargs):
        self.commands.append({"argv": argv, "timeout": kwargs["timeout"]})
        if argv[0] == "virt-cat":
            name = Path(argv[2]).name
            role = next(role for role, entry in artifacts.images.ROLE_IMAGES.items()
                        if entry[0] == name)
            manifest = "".join(package + "\tfixture-version\n"
                               for package in sorted(artifacts.images.ROLE_PACKAGES[role]))
            return subprocess.CompletedProcess(argv, 0, manifest)
        name = Path(argv[-1]).name
        sizes = {filename: size for filename, size in artifacts.images.ROLE_IMAGES.values()}
        size = sizes[name]
        if isinstance(size, tuple):
            size = size[0]
        return subprocess.CompletedProcess(argv, 0, json.dumps({"format": "qcow2", "virtual-size": size}))

    def run_lab(self, resume=False):
        return orchestrator.run_acceptance(self.adapter, self.root / "journal.json",
                                            "lab-offline123", resume=resume)

    def test_real_parsers_preserve_incomplete_evidence(self):
        result = self.run_lab()
        self.assertEqual(result["steps"]["telemetry"]["status"], "PASS")
        self.assertEqual(result["steps"]["report"]["status"], "FAILED")
        self.assertEqual(result["status"], "FAILED")
        failed = result["steps"]["report"]["evidence"]["probe"]
        self.assertFalse(failed["incident_report"]["evidence_quality"]["complete_evidence_verified"])
        evidence = result["steps"]["telemetry"]["evidence"]["probe"]
        self.assertEqual(evidence["incident_report"]["counters"]["metrics"]["xdp"]["drop"], 40)
        self.assertEqual(evidence["incident_report"]["attack_attribution"], "unverified")
        self.assertEqual(len(evidence["artifact_sha256"]), 9)
        self.assertTrue(all(command["argv"][:3] == ["qemu-img", "info", "--output=json"]
                            or command["argv"][:2] == ["virt-cat", "-a"]
                            for command in self.commands))

    def test_image_checksum_mismatch_prevents_dispatch(self):
        name = artifacts.images.ROLE_IMAGES["victim"][0]
        (self.image_dir / name).write_bytes(b"modified fixture")
        result = self.run_lab()
        self.assertEqual(result["steps"]["preflight"]["status"], "FAILED")
        self.assertEqual(self.operations.actions, [])

    def test_image_info_timeout_prevents_dispatch(self):
        def timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        self.adapter.image_runner = timeout
        self.assertEqual(self.run_lab()["steps"]["preflight"]["status"], "FAILED")
        self.assertEqual(self.operations.actions, [])

    def test_changed_xdp_identity_fails_telemetry(self):
        fingerprint = json.loads((self.experiment / "fingerprint-after.json").read_text())
        fingerprint["program_id"] = 8
        self.write("fingerprint-after.json", fingerprint)
        self.assertEqual(self.run_lab()["steps"]["telemetry"]["status"], "FAILED")
        self.assertNotIn("report", self.operations.actions)

    def test_unrelated_suricata_alert_fails_telemetry(self):
        alert = json.loads((self.experiment / "eve.json").read_text())
        alert["src_ip"] = "100.64.0.99"
        self.write("eve.json", alert)
        self.assertEqual(self.run_lab()["steps"]["telemetry"]["status"], "FAILED")

    def test_counter_reset_fails_before_telemetry_dispatch(self):
        self.write("after.json", {"loaded": 1, "syn": 1, "drop": 0, "pass": 1})
        self.assertEqual(self.run_lab()["steps"]["telemetry"]["status"], "FAILED")
        self.assertNotIn("telemetry", self.operations.actions)

    def test_missing_telemetry_artifact_fails(self):
        (self.experiment / "events.jsonl").unlink()
        self.assertEqual(self.run_lab()["steps"]["telemetry"]["status"], "FAILED")
        self.assertNotIn("report", self.operations.actions)

    def test_resume_rechecks_image_inputs(self):
        self.run_lab()
        name = artifacts.images.ROLE_IMAGES["client"][0]
        (self.image_dir / (name + ".role")).write_text("attacker")
        self.operations.actions.clear()
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
        self.assertEqual(self.operations.actions, [])

    def test_artifact_symlink_rejected(self):
        target = self.experiment / "eve.json"
        target.rename(self.experiment / "original.json")
        target.symlink_to(self.experiment / "original.json")
        self.assertEqual(self.run_lab()["steps"]["telemetry"]["status"], "FAILED")

    def test_artifact_hardlink_rejected(self):
        target = self.experiment / "eve.json"
        external = self.root / "eve-original.json"
        external.write_bytes(target.read_bytes())
        target.unlink()
        target.hardlink_to(external)
        self.assertEqual(self.run_lab()["steps"]["telemetry"]["status"], "FAILED")

    def test_operation_binding_survives_artifact_adapter_resume(self):
        from test_lifecycle_operations import Backend, operations
        backend = Backend()
        backend.failure = "health"
        self.adapter.operations = operations.OperationsAdapter(backend)
        self.assertEqual(self.run_lab()["steps"]["health"]["status"], "FAILED")
        backend.failure = None
        self.adapter.operations = operations.OperationsAdapter(backend)
        result = self.run_lab(resume=True)
        self.assertEqual(result["steps"]["telemetry"]["status"], "PASS")
        self.assertEqual(result["steps"]["report"]["status"], "FAILED")
        self.assertEqual(len(backend.commands), 2)
        self.assertEqual(self.adapter.operations.actual_lab_id, backend.actual)

    def enable_current_health(self, change=None):
        self.adapter.clock = lambda: 1000
        self.adapter.expected_host_key = "SHA256:fixture-pinned"
        self.adapter.max_health_age = 30
        async def provider(step, lab):
            observation = {
                "lab_id": lab, "sampled_at": 1000,
                "management": {"name": "mgmt0", "ifindex": 2, "route_interface": "mgmt0",
                               "host_key_fingerprint": "SHA256:fixture-pinned"},
                "protected": {"name": "data0", "ifindex": 3,
                              "xdp": {"attached": "drv", "prog_id": 7}},
                "snapshot": {"loaded": 1, "ids_enabled": 1, "ids_up": 1},
                "fingerprint": json.loads((self.experiment / "fingerprint-after.json").read_text()),
                "suricata_service": "active",
                "client": {"sampled_at": 1000, "source_role": "client", "target_role": "victim",
                           "returncode": 0, "http_status": 200},
            }
            if change is not None:
                change(step, observation)
            return observation
        self.adapter.health_provider = provider

    def test_current_health_uses_independent_management_and_client(self):
        self.enable_current_health()
        result = self.run_lab()
        self.assertEqual(result["steps"]["health"]["status"], "PASS")
        observed = result["steps"]["health"]["evidence"]["probe"]["current_health"]
        self.assertEqual(observed["management"]["name"], "mgmt0")
        self.assertEqual(result["steps"]["report"]["status"], "FAILED")

    def test_stale_current_health_blocks_creation(self):
        self.enable_current_health(lambda _, data: data.update(sampled_at=900))
        self.assertEqual(self.run_lab()["steps"]["preflight"]["status"], "FAILED")
        self.assertNotIn("create", self.operations.actions)

    def test_shared_or_misrouted_management_is_rejected(self):
        for field, value in (("name", "data0"), ("ifindex", 3),
                             ("route_interface", "data0"), ("host_key_fingerprint", "SHA256:other")):
            with self.subTest(field=field):
                self.enable_current_health(lambda _, data: data["management"].update({field: value}))
                with self.assertRaisesRegex(ValueError, "management path"):
                    asyncio.run(self.adapter.current_health("preflight", "lab-offline123"))

    def test_suricata_inactive_overrides_optimistic_backend(self):
        def change(step, data):
            if step == "configure":
                data["suricata_service"] = "inactive"
        self.enable_current_health(change)
        result = self.run_lab()
        self.assertEqual(result["steps"]["configure"]["status"], "FAILED")
        self.assertNotIn("health", self.operations.actions)

    def test_wrong_attached_xdp_program_blocks(self):
        self.enable_current_health(lambda _, data: data["protected"]["xdp"].update(prog_id=999))
        self.assertEqual(self.run_lab()["steps"]["configure"]["status"], "FAILED")

    def test_victim_local_probe_does_not_prove_client_health(self):
        self.enable_current_health(lambda _, data: data["client"].update(source_role="victim"))
        self.assertEqual(self.run_lab()["steps"]["health"]["status"], "FAILED")

    def test_resume_rechecks_management_path_before_actions(self):
        self.enable_current_health()
        self.run_lab()
        self.operations.actions.clear()
        self.enable_current_health(lambda _, data: data["management"].update(route_interface="data0"))
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
        self.assertEqual(self.operations.actions, [])


if __name__ == "__main__":
    unittest.main()
