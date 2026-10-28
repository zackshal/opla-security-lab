import importlib.util
import fcntl
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "bin/opla-lab-progress.py"
)

spec = importlib.util.spec_from_file_location(
    "opla_progress_test",
    SCRIPT,
)

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProgressTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.folder = Path(self.tmp.name)
        self.folder.chmod(0o700)

        self.path = self.folder / "state.json"
        self.lab = "lab-test1234"

    def test_success_persists_four_steps(self):
        result = module.run_offline(
            lambda _: True,
            self.path,
            self.lab,
        )

        self.assertTrue(
            all(
                record["status"] == "PASS"
                for record in result["steps"].values()
            )
        )

        persisted = module.read_state(self.path, self.lab)

        self.assertEqual(
            persisted["steps"]["create"]["attempts"],
            1,
        )

    def test_resume_skips_completed_create(self):
        calls = []

        def first(name):
            calls.append(name)
            return name != "configure"

        module.run_offline(first, self.path, self.lab)
        calls.clear()

        result = module.run_offline(
            lambda name: calls.append(name) or True,
            self.path,
            self.lab,
            resume=True,
        )

        self.assertEqual(calls, ["configure", "health"])
        self.assertEqual(
            result["steps"]["create"]["attempts"],
            1,
        )

    def test_failed_create_blocks_retry(self):
        module.run_offline(
            lambda name: name != "create",
            self.path,
            self.lab,
        )

        with self.assertRaisesRegex(
            module.Blocked, "reconcile"
        ):
            module.run_offline(
                lambda _: True,
                self.path,
                self.lab,
                resume=True,
            )

    def test_interrupted_running_blocks(self):
        state = module.run_offline(
            lambda _: True,
            self.path,
            self.lab,
        )

        state["steps"]["configure"]["status"] = "RUNNING"
        state["steps"]["health"] = {"status": "PENDING", "attempts": 0}
        module.save_state(self.path, state)

        with self.assertRaisesRegex(
            module.Blocked, "interrupted"
        ):
            module.run_offline(
                lambda _: True,
                self.path,
                self.lab,
                resume=True,
            )

    def test_reuse_requires_resume(self):
        module.run_offline(
            lambda _: True,
            self.path,
            self.lab,
        )

        with self.assertRaisesRegex(
            module.Blocked, "explicit resume"
        ):
            module.run_offline(
                lambda _: True,
                self.path,
                self.lab,
            )

    def test_symlink_journal_rejected(self):
        target = self.folder / "target"
        target.write_text("untouched")

        self.path.symlink_to(target)

        with self.assertRaisesRegex(
            module.Blocked, "symlink"
        ):
            module.run_offline(
                lambda _: True,
                self.path,
                self.lab,
            )

        self.assertEqual(
            target.read_text(),
            "untouched",
        )

    def test_nested_symlink_ancestor_is_rejected(self):
        real = self.folder / "real"
        real.mkdir()
        alias = self.folder / "alias"
        alias.symlink_to(real, target_is_directory=True)
        path = alias / "nested" / "journal.json"
        with self.assertRaisesRegex(module.Blocked, "symlink ancestor"):
            module.run_offline(lambda _: True, path, self.lab)

    def test_different_lab_rejected(self):
        module.run_offline(
            lambda _: True,
            self.path,
            self.lab,
        )

        with self.assertRaisesRegex(
            module.Blocked, "mismatch"
        ):
            module.run_offline(
                lambda _: True,
                self.path,
                "lab-diff5678",
                resume=True,
            )

    def test_corrupt_journal_blocks_without_executor_or_rewrite(self):
        state = module.run_offline(lambda _: True, self.path, self.lab)
        cases = [b"{", b"\xff", b"[]"]
        for attempts in (-1, True, "1", None, 0):
            broken = json.loads(json.dumps(state))
            broken["steps"]["create"]["attempts"] = attempts
            cases.append(json.dumps(broken).encode())
        broken = json.loads(json.dumps(state))
        broken["steps"]["create"]["status"] = "FAILED"
        cases.append(json.dumps(broken).encode())
        for data in cases:
            with self.subTest(data=data):
                self.path.write_bytes(data)
                calls = []
                with self.assertRaises(module.Blocked):
                    module.run_offline(lambda name: calls.append(name),
                                       self.path, self.lab, resume=True)
                self.assertEqual(calls, [])
                self.assertEqual(self.path.read_bytes(), data)

    def test_pass_without_evidence_or_finished_at_is_rejected(self):
        state = module.run_offline(lambda _: True, self.path, self.lab)
        for field in ("evidence", "finished_at"):
            broken = json.loads(json.dumps(state))
            broken["steps"]["create"].pop(field, None)
            module.save_state(self.path, broken)
            with self.subTest(field=field), self.assertRaisesRegex(
                    module.Blocked, "PASS stage"):
                module.run_offline(lambda _: self.fail("executor called"),
                                   self.path, self.lab, resume=True)

    def test_pass_with_invalid_timestamps_is_rejected(self):
        state = module.run_offline(lambda _: True, self.path, self.lab)
        for field, value in (("started_at", ""), ("finished_at", "not-a-time"),
                             ("finished_at", "2026-10-28T12:00:00")):
            broken = json.loads(json.dumps(state))
            broken["steps"]["create"][field] = value
            module.save_state(self.path, broken)
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    module.Blocked, "PASS stage"):
                module.run_offline(lambda _: self.fail("executor called"),
                                   self.path, self.lab, resume=True)

    def test_abrupt_stop_at_every_stage_blocks_resume(self):
        for stage in module.STEPS:
            with self.subTest(stage=stage):
                path = self.folder / (stage + ".json")

                def interrupt(name):
                    if name == stage:
                        raise KeyboardInterrupt()
                    return True

                with self.assertRaises(KeyboardInterrupt):
                    module.run_offline(interrupt, path, self.lab)
                state = module.read_state(path, self.lab)
                self.assertEqual(state["steps"][stage]["status"], "RUNNING")
                calls = []
                with self.assertRaisesRegex(module.Blocked, "interrupted"):
                    module.run_offline(lambda name: calls.append(name), path,
                                       self.lab, resume=True)
                self.assertEqual(calls, [])

    def test_concurrent_lock_blocks_without_journal(self):
        with Path(str(self.path) + ".lock").open("w") as lock:
            Path(lock.name).chmod(0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(module.Blocked, "locked"):
                module.run_offline(lambda _: self.fail("executor called"),
                                   self.path, self.lab)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
