"""End-to-end lifecycle faults with pure in-memory adapters and temp journals."""

import asyncio
import fcntl
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "bin/opla-lab-orchestrator.py"
spec = importlib.util.spec_from_file_location("acceptance_orchestrator", SCRIPT)
orchestrator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = orchestrator
spec.loader.exec_module(orchestrator)


def stable_report(report):
    """Remove wall-clock values only; retain statuses, evidence and attempts."""
    report = json.loads(json.dumps(report))
    for record in report["steps"].values():
        for key in ("started_at", "finished_at"):
            if key in record:
                record[key] = "<timestamp>"
    return report


class FakeAdapter:
    mode = "offline"

    def __init__(self):
        self.actions = []
        self.probes = []
        self.completed = set()
        self.failure = None
        self.missing = None
        self.wrong_identity = False
        self.hang = None
        self.cancelled = False
        self.interrupt = None

    async def execute(self, step, lab_id):
        self.actions.append(step)
        if self.interrupt == step:
            raise SystemExit("simulated abrupt stop")
        if self.hang == step:
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True
        if self.failure == step:
            raise RuntimeError("injected " + step + " failure")
        self.completed.add(step)
        return {"lab_id": lab_id, "source": "fake", "operation": step}

    async def probe(self, step, lab_id):
        self.probes.append(step)
        if self.hang == "probe:" + step:
            await asyncio.Event().wait()
        return {
            "lab_id": "lab-other123" if self.wrong_identity else lab_id,
            **{key: step in self.completed and (step, key) != self.missing
               for key in orchestrator.REQUIRED_PROBES[step]},
        }


class LifecycleAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.json"
        self.lab = "lab-offline123"
        self.adapter = FakeAdapter()

    def run_lab(self, **kwargs):
        return orchestrator.run_acceptance(
            self.adapter, self.path, self.lab, timeout=0.02, **kwargs
        )

    def test_success_requires_all_probes_and_persists_evidence(self):
        report = self.run_lab()
        self.assertEqual(report["status"], "PASS")
        self.assertFalse(report["actual_execution"])
        self.assertEqual(report["live_status"], "NOT TESTED")
        self.assertEqual(self.adapter.actions, list(orchestrator.ACCEPTANCE_STEPS))
        saved = json.loads(self.path.read_text())
        for step in orchestrator.ACCEPTANCE_STEPS:
            self.assertEqual(saved["steps"][step]["evidence"]["probe"]["lab_id"], self.lab)
        sample = SCRIPT.parents[1] / "docs/examples/lifecycle-offline-pass.json"
        self.assertEqual(stable_report(report), json.loads(sample.read_text()))

    def test_action_failure_at_every_boundary_stops_downstream(self):
        for step in orchestrator.ACCEPTANCE_STEPS:
            with self.subTest(step=step):
                self.path = Path(self.tmp.name) / (step + ".json")
                self.adapter = FakeAdapter()
                self.adapter.failure = step
                report = self.run_lab()
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(report["steps"][step]["status"], "FAILED")
                self.assertEqual(self.adapter.actions[-1], step)
                self.assertIn("injected", report["steps"][step]["error"])

    def test_missing_probes_fail_closed_at_every_boundary(self):
        for step, keys in orchestrator.REQUIRED_PROBES.items():
            for key in keys:
                with self.subTest(step=step, key=key):
                    self.path = Path(self.tmp.name) / (step + key + ".json")
                    self.adapter = FakeAdapter()
                    self.adapter.missing = (step, key)
                    report = self.run_lab()
                    self.assertEqual(report["status"], "FAILED")
                    self.assertEqual(self.adapter.actions[-1], step)

    def test_resume_after_configure_failure_revalidates_and_reuses_create(self):
        self.adapter.failure = "configure"
        self.run_lab()
        self.adapter.failure = None
        self.adapter.actions.clear()
        self.adapter.probes.clear()
        self.assertEqual(self.run_lab(resume=True)["status"], "PASS")
        self.assertEqual(self.adapter.actions, list(orchestrator.ACCEPTANCE_STEPS[2:]))
        self.assertEqual(self.adapter.probes[:2], ["preflight", "create"])

    def test_completed_resume_reprobes_without_repeating_actions(self):
        self.run_lab()
        self.adapter.actions.clear()
        self.adapter.probes.clear()
        self.assertEqual(self.run_lab(resume=True)["status"], "PASS")
        self.assertEqual(self.adapter.actions, [])
        self.assertEqual(self.adapter.probes, list(orchestrator.ACCEPTANCE_STEPS))

    def test_resource_drift_blocks_resume_and_is_recorded(self):
        self.adapter.failure = "configure"
        self.run_lab()
        self.adapter.missing = ("create", "ownership")
        self.adapter.actions.clear()
        report = self.run_lab(resume=True)
        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(self.adapter.actions, [])
        self.assertIn("last_blocked", json.loads(self.path.read_text()))

    def test_failed_create_never_retried(self):
        self.adapter.failure = "create"
        self.run_lab()
        self.adapter.actions.clear()
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
        self.assertEqual(self.adapter.actions, [])

    def test_abrupt_stop_at_every_boundary_never_replayed(self):
        for step in orchestrator.ACCEPTANCE_STEPS:
            with self.subTest(step=step):
                self.path = Path(self.tmp.name) / (step + ".json")
                self.adapter = FakeAdapter()
                self.adapter.interrupt = step
                with self.assertRaises(SystemExit):
                    self.run_lab()
                self.adapter.actions.clear()
                self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
                self.assertEqual(self.adapter.actions, [])

    def test_action_and_probe_timeout_are_failures(self):
        for hang in ("create", "probe:create"):
            with self.subTest(hang=hang):
                self.path = Path(self.tmp.name) / (hang.replace(":", "-") + ".json")
                self.adapter = FakeAdapter()
                self.adapter.hang = hang
                report = self.run_lab()
                self.assertEqual(report["steps"]["create"]["status"], "FAILED")
                self.assertIn("TimeoutError", report["steps"]["create"]["error"])
                self.assertEqual(
                    report["steps"]["create"]["evidence"]["deadline"],
                    {"stage": "create", "timeout_seconds": 0.02,
                     "kind": "stage_timeout"},
                )
                if hang == "create":
                    self.assertTrue(self.adapter.cancelled)
                self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")

    def test_identity_mismatch_never_passes(self):
        self.adapter.wrong_identity = True
        self.assertEqual(self.run_lab()["status"], "FAILED")
        self.assertEqual(self.adapter.actions, ["preflight"])

    def test_concurrent_lock_prevents_actions_and_probes(self):
        lock_path = Path(str(self.path) + ".lock")
        lock_path.touch(mode=0o600)
        with lock_path.open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_lab()["status"], "BLOCKED")
        self.assertEqual(self.adapter.actions, [])
        self.assertEqual(self.adapter.probes, [])

    def test_live_adapter_refused(self):
        self.adapter.mode = "live"
        with self.assertRaises(orchestrator.progress.Blocked):
            self.run_lab()
        self.assertFalse(self.path.exists())

    def test_corrupt_journal_blocks_without_adapter_calls(self):
        self.path.write_text('{"version": 1}')
        self.path.chmod(0o600)
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
        self.assertEqual(self.adapter.actions, [])
        self.assertEqual(self.adapter.probes, [])

    def test_plan_change_cannot_reinterpret_a_completed_journal(self):
        self.run_lab()
        state = json.loads(self.path.read_text())
        state["plan"].reverse()
        self.path.write_text(json.dumps(state))
        self.adapter.actions.clear()
        self.assertEqual(self.run_lab(resume=True)["status"], "BLOCKED")
        self.assertEqual(self.adapter.actions, [])

    def test_invalid_deadline_refused(self):
        for value in (0, -1, True, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                orchestrator.run_acceptance(self.adapter, self.path, self.lab, timeout=value)

    def test_stage_deadlines_are_selected_for_each_action_and_probe(self):
        stage_timeouts = {
            step: index + 0.5
            for index, step in enumerate(orchestrator.ACCEPTANCE_STEPS, 1)
        }
        observed = []
        original_wait_for = orchestrator.asyncio.wait_for

        async def capture(awaitable, *, timeout):
            observed.append(timeout)
            return await original_wait_for(awaitable, timeout=timeout)

        with patch.object(orchestrator.asyncio, "wait_for", capture):
            self.assertEqual(
                self.run_lab(stage_timeouts=stage_timeouts)["status"], "PASS"
            )

        counts = {step: observed.count(value)
                  for step, value in stage_timeouts.items()}
        self.assertEqual(counts["preflight"], 3)
        self.assertTrue(all(counts[step] >= 2 for step in orchestrator.ACCEPTANCE_STEPS[1:]))
        self.assertEqual(set(observed), set(stage_timeouts.values()))

    def test_invalid_stage_deadline_map_is_rejected_before_adapter_calls(self):
        invalid_maps = (
            [],
            {"unknown": 1},
            {"create": 0},
            {"create": -1},
            {"create": True},
            {"create": float("nan")},
            {"create": float("inf")},
            {"create": "1"},
        )
        for value in invalid_maps:
            with self.subTest(value=value), self.assertRaises(ValueError):
                orchestrator.run_acceptance(
                    self.adapter, self.path, self.lab, stage_timeouts=value
                )
        self.assertEqual(self.adapter.actions, [])
        self.assertEqual(self.adapter.probes, [])

    def test_stage_timeout_preserves_failure_and_allows_configure_resume(self):
        self.adapter.hang = "configure"
        report = self.run_lab(stage_timeouts={"configure": 0.001})
        self.assertEqual(report["steps"]["configure"]["status"], "FAILED")
        self.assertIn("TimeoutError", report["steps"]["configure"]["error"])
        self.assertEqual(
            report["steps"]["configure"]["evidence"]["deadline"],
            {"stage": "configure", "timeout_seconds": 0.001,
             "kind": "stage_timeout"},
        )
        self.adapter.hang = None
        self.adapter.actions.clear()
        self.assertEqual(self.run_lab(resume=True)["status"], "PASS")
        self.assertEqual(self.adapter.actions, list(orchestrator.ACCEPTANCE_STEPS[2:]))


if __name__ == "__main__":
    unittest.main()
