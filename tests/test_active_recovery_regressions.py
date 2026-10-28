"""Safe regression tests for active recovery journal and retry semantics."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opla_active_recovery_regressions",
    ROOT / "bin/opla-active-creation-recover.py",
)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)

LAB = "lab-Regress123"
CONFIRM = "RECOVER-CREATION:" + LAB


class ActiveRecoveryRegressionTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="opla-recovery-regression-"
        )
        self.root = Path(self.temp.name)
        self.labdir = self.root / LAB
        self.labdir.mkdir()

        self.sentinel = self.labdir / "KEEP.txt"
        self.sentinel.write_text("preserve this file\n")

        self.safe_root_patch = patch.object(
            recovery.prune,
            "safe_root",
            side_effect=lambda value: Path(value),
        )
        self.lock_patch = patch.object(
            recovery.rollback,
            "lock_is_safe",
            return_value=True,
        )

        self.safe_root_patch.start()
        self.lock_patch.start()

    def tearDown(self):
        self.lock_patch.stop()
        self.safe_root_patch.stop()
        self.temp.cleanup()

    def recover(self, audit, evidence, stop, offline):
        return recovery.locked_recover(
            self.root,
            LAB,
            CONFIRM,
            audit=audit,
            evidence=evidence,
            stop=stop,
            offline=offline,
        )

    def journal_records(self):
        path = self.root / "operations/lab-cleanup.jsonl"
        self.assertTrue(path.is_file(), "Real journal was not created")

        return [
            json.loads(line)
            for line in path.read_text().splitlines()
            if line.strip()
        ]

    def test_stop_failure_records_failed_and_preserves_files(self):
        calls = []
        events = []
        original = recovery.prune.write_journal

        def journal(*args, **kwargs):
            result = original(*args, **kwargs)
            events.append(args[2])
            return result

        def stop(*_):
            calls.append("stop")
            raise RuntimeError("simulated QMP failure")

        def offline(*_):
            calls.append("offline")
            self.fail("Offline cleanup must not execute")

        with patch.object(recovery.prune, "write_journal", journal):
            with self.assertRaisesRegex(RuntimeError, "QMP failure"):
                self.recover(
                    audit=lambda *_: calls.append("audit"),
                    evidence=lambda *_: calls.append("evidence"),
                    stop=stop,
                    offline=offline,
                )

        self.assertEqual(
            calls,
            ["audit", "evidence", "audit", "evidence", "stop"],
        )
        self.assertEqual(events, ["planned", "failed"])
        self.assertGreaterEqual(len(self.journal_records()), 2)
        self.assertEqual(self.sentinel.read_text(), "preserve this file\n")
        self.assertNotIn("offline", calls)

    def test_post_stop_evidence_failure_blocks_deletion(self):
        calls = []
        events = []
        evidence_count = 0
        original = recovery.prune.write_journal

        def journal(*args, **kwargs):
            result = original(*args, **kwargs)
            events.append(args[2])
            return result

        def evidence(*_):
            nonlocal evidence_count
            evidence_count += 1
            calls.append(f"evidence#{evidence_count}")
            if evidence_count == 3:
                raise recovery.Blocked("untracked process references lab")
            return {}

        def offline(*_):
            self.fail("Offline cleanup must not execute")

        with patch.object(recovery.prune, "write_journal", journal):
            with self.assertRaisesRegex(
                recovery.Blocked, "untracked process"
            ):
                self.recover(
                    audit=lambda *_: calls.append("audit"),
                    evidence=evidence,
                    stop=lambda *_: calls.append("stop"),
                    offline=offline,
                )

        self.assertEqual(
            calls,
            [
                "audit", "evidence#1",
                "audit", "evidence#2",
                "stop", "evidence#3",
            ],
        )
        self.assertEqual(events, ["planned", "failed"])
        self.assertGreaterEqual(len(self.journal_records()), 2)
        self.assertTrue(self.sentinel.exists())

    def test_retry_persists_failure_and_completion(self):
        attempts = 0
        offline_count = 0
        events = []
        original = recovery.prune.write_journal

        def journal(*args, **kwargs):
            result = original(*args, **kwargs)
            events.append(args[2])
            return result

        def stop(*_):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("temporary QMP failure")

        def offline(*_):
            nonlocal offline_count
            offline_count += 1
            return {"test_only": True}

        with patch.object(recovery.prune, "write_journal", journal):
            with self.assertRaisesRegex(
                RuntimeError, "temporary QMP failure"
            ):
                self.recover(
                    audit=lambda *_: {},
                    evidence=lambda *_: {},
                    stop=stop,
                    offline=offline,
                )

            self.assertEqual(offline_count, 0)

            result = self.recover(
                audit=lambda *_: {},
                evidence=lambda *_: {},
                stop=stop,
                offline=offline,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(offline_count, 1)
        self.assertEqual(attempts, 2)
        self.assertEqual(
            events,
            ["planned", "failed", "planned", "completed"],
        )
        self.assertGreaterEqual(len(self.journal_records()), 4)
        self.assertTrue(self.sentinel.exists())


if __name__ == "__main__":
    unittest.main()
