"""Generated lab identity and command cancellation with a pure fake backend."""

import asyncio
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from tests.test_lifecycle_acceptance import FakeAdapter, orchestrator

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lab_operations", ROOT / "bin/opla-lab-operations.py")
operations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operations)


class Backend(FakeAdapter):
    def __init__(self):
        super().__init__()
        self.actual = "lab-generated123"
        self.output = "logs\nOPLA_CREATED_LAB_ID=" + self.actual + "\n"
        self.commands = []
        self.identities = []
        self.stopped = []
        self.timeout_stage = None
        self.cleanup_failure = False
        self.exit_code = 0

    async def run(self, command_id, argv):
        step = "create" if argv[1] == "bin/opla-create-launcher.py" else "configure"
        self.commands.append((command_id, argv))
        if step == self.timeout_stage:
            await asyncio.Event().wait()
        self.completed.add(step)
        return subprocess.CompletedProcess(argv, self.exit_code, self.output if step == "create" else "", "")

    async def stop_process_tree(self, command_id):
        self.stopped.append(command_id)
        if self.cleanup_failure:
            raise RuntimeError("mock process group did not exit")
        return {"status": "stopped", "mock_children_waited": True}

    async def probe(self, step, lab_id):
        self.identities.append((step, lab_id))
        return await super().probe(step, lab_id)


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.json"
        self.backend = Backend()
        self.adapter = operations.OperationsAdapter(self.backend)

    def run_lab(self, resume=False):
        return orchestrator.run_acceptance(self.adapter, self.path, "lab-request123",
                                            resume=resume, timeout=0.02)

    def test_generated_id_is_used_and_persisted(self):
        result = self.run_lab()
        self.assertEqual(result["status"], "PASS")
        create = result["steps"]["create"]["evidence"]["action"]
        self.assertEqual(create["actual_lab_id"], self.backend.actual)
        self.assertEqual(self.backend.commands[1][1][-2:], [self.backend.actual] * 2)
        for stage, identity in self.backend.identities:
            if stage != "preflight":
                self.assertEqual(identity, self.backend.actual)
        self.assertEqual(len(create["command"]["stdout_sha256"]), 64)
        self.assertNotIn("stdout", create["command"])

    def test_fresh_adapter_restores_binding_before_resume(self):
        self.backend.failure = "health"
        self.assertEqual(self.run_lab()["status"], "FAILED")
        self.backend.failure = None
        self.adapter = operations.OperationsAdapter(self.backend)
        self.assertEqual(self.run_lab(resume=True)["status"], "PASS")
        self.assertEqual(len(self.backend.commands), 2)
        self.assertEqual(self.adapter.actual_lab_id, self.backend.actual)

    def test_invalid_or_ambiguous_created_id_blocks_replay(self):
        for output in ("", "OPLA_CREATED_LAB_ID=../../evil", self.backend.output * 2):
            with self.subTest(output=output):
                self.path = Path(self.tmp.name) / (str(len(output)) + ".json")
                self.backend = Backend()
                self.backend.output = output
                self.adapter = operations.OperationsAdapter(self.backend)
                self.assertEqual(self.run_lab()["steps"]["create"]["status"], "FAILED")
                self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")

    def test_timeout_stops_mock_process_tree_and_blocks_resume(self):
        for stage in ("create", "configure"):
            with self.subTest(stage=stage):
                self.path = Path(self.tmp.name) / (stage + ".json")
                self.backend = Backend()
                self.backend.timeout_stage = stage
                self.adapter = operations.OperationsAdapter(self.backend)
                result = self.run_lab()
                evidence = result["steps"][stage]["evidence"]
                self.assertTrue(evidence["reconciliation_required"])
                self.assertEqual(evidence["process_cleanup"]["status"], "stopped")
                self.assertEqual(self.backend.stopped, [evidence["command_id"]])
                self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")

    def test_cleanup_failure_preserves_uncertainty(self):
        self.backend.timeout_stage = "create"
        self.backend.cleanup_failure = True
        result = self.run_lab()
        evidence = result["steps"]["create"]["evidence"]
        self.assertEqual(evidence["process_cleanup"]["status"], "unknown")
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")

    def test_missing_persisted_binding_blocks_before_commands(self):
        self.run_lab()
        state = json.loads(self.path.read_text())
        del state["steps"]["create"]["evidence"]["action"]["actual_lab_id"]
        self.path.write_text(json.dumps(state))
        self.adapter = operations.OperationsAdapter(self.backend)
        self.backend.commands.clear()
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
        self.assertEqual(self.backend.commands, [])

    def test_nonzero_create_exit_has_command_evidence(self):
        self.backend.exit_code = 2
        result = self.run_lab()
        self.assertEqual(result["steps"]["create"]["evidence"]["returncode"], 2)
        self.assertIsNone(self.adapter.actual_lab_id)

    def test_create_marker_follows_ready_receipt(self):
        source = (ROOT / "bin/create-lab.sh").read_text()
        self.assertLess(source.index('opla-registry.py" ready'), source.index("OPLA_CREATED_LAB_ID="))

    def test_command_is_durable_before_dispatch(self):
        run = self.backend.run
        async def inspect_before_run(command_id, argv):
            state = json.loads(self.path.read_text())
            stage = "create" if argv[1].endswith("opla-create-launcher.py") else "configure"
            record = state["steps"][stage]
            self.assertEqual(record["status"], "RUNNING")
            self.assertEqual(record["commands"][-1]["command_id"], command_id)
            self.assertEqual(record["commands"][-1]["status"], "PREPARED")
            self.assertEqual(record["commands"][-1]["argv"], argv)
            return await run(command_id, argv)
        self.backend.run = inspect_before_run
        self.assertEqual(self.run_lab()["status"], "PASS")
        self.assertIsNone(self.adapter.checkpoint)

    def test_abrupt_stop_keeps_command_id_and_prevents_replay(self):
        async def stop(command_id, argv):
            raise SystemExit("abrupt mock stop")
        self.backend.run = stop
        with self.assertRaises(SystemExit):
            self.run_lab()
        state = json.loads(self.path.read_text())
        self.assertEqual(state["steps"]["create"]["commands"][0]["status"], "PREPARED")
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
        self.assertIsNone(self.adapter.checkpoint)

    def test_checkpoint_write_failure_prevents_dispatch(self):
        save = orchestrator.progress.save_state
        failed = False
        def fail_once(path, state):
            nonlocal failed
            if state["steps"]["create"].get("commands") and not failed:
                failed = True
                raise OSError("simulated fsync failure")
            return save(path, state)
        with patch.object(orchestrator.progress, "save_state", side_effect=fail_once):
            self.assertEqual(self.run_lab()["steps"]["create"]["status"], "FAILED")
        self.assertTrue(failed)
        self.assertEqual(self.backend.commands, [])
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")

    def test_unfinished_configure_checkpoint_blocks_even_without_error_evidence(self):
        self.run_lab()
        state = json.loads(self.path.read_text())
        record = state["steps"]["configure"]
        record["status"] = "FAILED"
        record.pop("evidence")
        record["commands"][0].update(status="PREPARED", reconciliation_required=True)
        for step in orchestrator.ACCEPTANCE_STEPS[3:]:
            state["steps"][step] = {"status": "PENDING", "attempts": 0}
        self.path.write_text(json.dumps(state))
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")

    def test_corrupt_checkpoint_blocks_without_dispatch(self):
        self.run_lab()
        state = json.loads(self.path.read_text())
        for mutation in ({"argv": "shell text"}, {"status": "PREPARED"}):
            with self.subTest(mutation=mutation):
                broken = json.loads(json.dumps(state))
                broken["steps"]["create"]["commands"][0].update(mutation)
                self.path.write_text(json.dumps(broken))
                self.backend.commands.clear()
                self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
                self.assertEqual(self.backend.commands, [])


class RegistryProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backend = Backend()
        self.operations = operations.OperationsAdapter(self.backend)
        self.operations.actual_lab_id = self.backend.actual
        self.backend.completed.add("create")
        self.seen = []
        def inspector(kind, name):
            self.seen.append((kind, name))
            return ("active" if kind.endswith("_unit") else "present"), "mock"
        self.adapter = operations.RegistryAdapter(self.operations, root=self.root, inspector=inspector)
        lab = self.root / self.backend.actual
        lab.mkdir()
        state = lab / "state.env"
        state.write_text(
            f"LAB_ID={self.backend.actual}\nBRIDGE=br-op7\nSUBNET=100.64.0.0/29\n"
            "MGMT_BRIDGE=br-op8\nMGMT_SUBNET=100.64.0.8/29\n"
            "MGMT_GW=100.64.0.9\nATTACKER_MGMT_IP=100.64.0.10\n"
            "VICTIM_MGMT_IP=100.64.0.11\nCLIENT_MGMT_IP=100.64.0.12\n"
        )
        state.chmod(0o600)
        self.adapter.verifier.reg.persist(self.root, self.backend.actual, "ready")

    def probe(self):
        return asyncio.run(self.adapter.probe("create", "lab-request123"))

    def test_receipt_presence_never_proves_ownership(self):
        result = self.probe()
        self.assertTrue(result["registry"])
        self.assertTrue(result["three_vms"])
        self.assertFalse(result["ownership"])
        self.assertEqual(len(self.seen), 20)
        self.assertFalse(result["registry_observations"][0]["verified_for_deletion"])

    def test_explicit_synthetic_attestation_enables_offline_ownership_only(self):
        def attest(lab_id, resources, records):
            return {"lab_id": lab_id, "resources": resources, "exclusive": True,
                    "cross_lab_conflict": False, "evidence_status": "synthetic"}
        self.adapter.ownership_attestor = attest
        result = self.probe()
        self.assertTrue(result["ownership"])
        self.assertEqual(result["ownership_attestation"]["evidence_status"], "synthetic")
        self.assertFalse(result["registry_observations"][0]["verified_for_deletion"])

    def test_attestation_identity_conflict_or_malformed_resources_fail_closed(self):
        cases = (
            {"lab_id": "lab-other123", "resources": [], "exclusive": True,
             "cross_lab_conflict": False, "evidence_status": "synthetic"},
            {"lab_id": self.backend.actual, "resources": [], "exclusive": True,
             "cross_lab_conflict": True, "evidence_status": "synthetic"},
            {"lab_id": self.backend.actual, "resources": "all", "exclusive": True,
             "cross_lab_conflict": False, "evidence_status": "synthetic"},
            {"lab_id": self.backend.actual, "resources": [], "exclusive": True,
             "cross_lab_conflict": False, "evidence_status": "unknown"},
        )
        for attestation in cases:
            with self.subTest(attestation=attestation):
                self.adapter.ownership_attestor = lambda *_args, value=attestation: value
                result = self.probe()
                self.assertFalse(result["ownership"])

    def test_partial_resource_observations_fail(self):
        self.adapter.inspector = lambda *_: ("missing", "mock")
        result = self.probe()
        self.assertFalse(result["registry"])
        self.assertFalse(result["three_vms"])
        self.assertFalse(result["ownership"])

    def test_poisoned_receipt_cannot_redirect_inspector(self):
        path = self.root / "registry" / (self.backend.actual + ".json")
        receipt = json.loads(path.read_text())
        receipt["resources"][0]["name"] = "/etc/passwd"
        path.write_text(json.dumps(receipt))
        result = self.probe()
        self.assertFalse(result["registry"])
        self.assertFalse(result["ownership"])
        self.assertEqual(self.seen, [])

    def test_incomplete_receipt_does_not_mean_ready(self):
        self.adapter.verifier.reg.persist(self.root, self.backend.actual, "creating")
        self.assertFalse(self.probe()["registry"])

    def test_missing_state_prevents_resource_inspection(self):
        (self.root / self.backend.actual / "state.env").unlink()
        self.assertFalse(self.probe()["registry"])
        self.assertEqual(self.seen, [])

    def test_registry_adapter_integration_blocks_unproven_ownership(self):
        self.operations.actual_lab_id = None
        path = self.root / "journal.json"
        result = orchestrator.run_acceptance(self.adapter, path, "lab-request123")
        self.assertEqual(result["steps"]["create"]["status"], "FAILED")
        self.assertEqual(result["steps"]["configure"]["status"], "NOT TESTED")
        probe = result["steps"]["create"]["evidence"]["probe"]
        self.assertTrue(probe["registry"])
        self.assertFalse(probe["ownership"])
        self.assertEqual(len(json.loads(path.read_text())["steps"]["create"]["commands"]), 1)
        self.assertIsNone(self.operations.checkpoint)

    def test_attested_registry_adapter_allows_offline_orchestrator_progress(self):
        def attest(lab_id, resources, records):
            return {"lab_id": lab_id, "resources": resources, "exclusive": True,
                    "cross_lab_conflict": False, "evidence_status": "synthetic"}
        self.adapter.ownership_attestor = attest
        self.operations.actual_lab_id = None
        result = orchestrator.run_acceptance(
            self.adapter, self.root / "attested-journal.json", "lab-request123")
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["actual_execution"])
        self.assertEqual(result["live_status"], "NOT TESTED")
        self.assertNotIn("READY", json.dumps(result))
        for step in orchestrator.ACCEPTANCE_STEPS:
            self.assertEqual(result["steps"][step]["status"], "PASS")
            probe = result["steps"][step]["evidence"]["probe"]
            if step != "preflight":
                self.assertTrue(probe["ownership"])
                for record in probe.get("registry_observations", []):
                    self.assertFalse(record["verified_for_deletion"])


if __name__ == "__main__":
    unittest.main()
