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

    def prepare_default_cleanup(self):
        registry = self.root / 'registry'
        registry.mkdir()
        receipt = registry / f'{LAB}.json'
        receipt.write_text('{"fixture": true}\n')
        return receipt

    def test_default_cleanup_branch_removes_only_temp_lab_and_receipt(self):
        receipt = self.prepare_default_cleanup()
        verification = {"fixture": "offline verified"}
        events = []

        def verify(root, lab):
            events.append('verify')
            self.assertEqual(root, self.root)
            self.assertEqual(lab, LAB)
            return verification

        with patch.object(recovery.secure, 'remove_stale_sockets',
                          side_effect=lambda *_: events.append('sockets')), \
             patch.object(recovery.rollback, 'verify', side_effect=verify):
            result = self.recover(
                audit=lambda *_: events.append('audit'),
                evidence=lambda *_: events.append('evidence'),
                stop=lambda *_: events.append('stop'),
                offline=None,
            )

        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['offline'], verification)
        self.assertEqual(events, ['audit', 'evidence', 'audit', 'evidence',
                                  'stop', 'evidence', 'sockets', 'verify', 'verify'])
        self.assertFalse(self.labdir.exists())
        self.assertFalse(receipt.exists())
        self.assertEqual([item['outcome'] for item in self.journal_records()],
                         ['planned', 'offline_verified', 'completed'])

    def test_default_cleanup_second_verification_failure_preserves_lab(self):
        receipt = self.prepare_default_cleanup()
        verify_count = 0
        original = recovery.prune.write_journal
        events = []

        def verify(*_):
            nonlocal verify_count
            verify_count += 1
            if verify_count == 2:
                raise recovery.Blocked('offline resources changed')
            return {"fixture": "offline verified"}

        with patch.object(recovery.prune, 'write_journal', wraps=original), \
             patch.object(recovery.secure, 'remove_stale_sockets',
                          side_effect=lambda *_: events.append('sockets')), \
             patch.object(recovery.rollback, 'verify', side_effect=verify):
            with self.assertRaisesRegex(recovery.Blocked, 'resources changed'):
                self.recover(
                    audit=lambda *_: None,
                    evidence=lambda *_: None,
                    stop=lambda *_: None,
                    offline=None,
                )

        self.assertEqual(verify_count, 2)
        self.assertTrue(self.sentinel.exists())
        self.assertTrue(receipt.exists())
        self.assertEqual([item['outcome'] for item in self.journal_records()],
                         ['planned', 'offline_verified', 'failed'])

    def test_default_cleanup_receipt_unlink_failure_is_durable_partial_state(self):
        receipt = self.prepare_default_cleanup()
        original_unlink = Path.unlink
        def fail_receipt(path, *args, **kwargs):
            if path == receipt:
                raise PermissionError('fixture receipt unlink failure')
            return original_unlink(path, *args, **kwargs)

        with patch.object(recovery.secure, 'remove_stale_sockets'), \
             patch.object(recovery.rollback, 'verify', return_value={'fixture': True}), \
             patch.object(Path, 'unlink', fail_receipt):
            with self.assertRaisesRegex(PermissionError, 'receipt unlink failure'):
                self.recover(
                    audit=lambda *_: None,
                    evidence=lambda *_: None,
                    stop=lambda *_: None,
                    offline=None,
                )

        self.assertFalse(self.labdir.exists())
        self.assertTrue(receipt.exists())
        self.assertEqual([item['outcome'] for item in self.journal_records()],
                         ['planned', 'offline_verified', 'failed'])

        def reconcile_only(root, lab):
            self.assertEqual(root, self.root)
            self.assertEqual(lab, LAB)
            self.assertFalse(self.labdir.exists())
            raise recovery.Blocked('lab directory missing after partial cleanup; manual receipt reconciliation required')

        with self.assertRaisesRegex(recovery.Blocked, 'manual receipt reconciliation'):
            self.recover(
                audit=reconcile_only,
                evidence=lambda *_: self.fail('must not inspect or clean after audit blocks'),
                stop=lambda *_: self.fail('must not stop after audit blocks'),
                offline=lambda *_: self.fail('must not retry deletion after audit blocks'),
            )
        self.assertTrue(receipt.exists())
        self.assertEqual([item['outcome'] for item in self.journal_records()],
                         ['planned', 'offline_verified', 'failed'])

    def test_untracked_open_fd_blocks_even_when_command_line_is_unrelated(self):
        proc_root = self.root / 'fake-proc'
        proc_root.mkdir()
        disk = self.labdir / 'victim' / 'disk.qcow2'
        disk.parent.mkdir()
        disk.write_bytes(b'fixture disk')
        units = {
            f'qemu-{LAB}-attacker.service': (201, 'qemu-system-x86_64',
                str(self.labdir / 'attacker' / 'disk.qcow2')),
            f'qemu-{LAB}-victim.service': (202, 'qemu-system-x86_64',
                str(self.labdir / 'victim' / 'disk.qcow2')),
            f'qemu-{LAB}-client.service': (203, 'qemu-system-x86_64',
                str(self.labdir / 'client' / 'disk.qcow2')),
            f'dhcp-{LAB}.service': (204, 'dnsmasq',
                str(self.labdir / 'dnsmasq.conf')),
        }
        for unit, (pid, binary, marker) in units.items():
            directory = proc_root / str(pid)
            (directory / 'fd').mkdir(parents=True)
            stat_tail = ['S', *(['0'] * 18), str(pid)]
            (directory / 'stat').write_text(
                f"{pid} ({binary}) " + ' '.join(stat_tail) + '\n')
            arg = ('--conf-file=' + marker) if binary == 'dnsmasq' else marker
            (directory / 'cmdline').write_bytes(
                binary.encode() + b'\0' + arg.encode() + b'\0')
            (directory / 'exe').symlink_to('/usr/sbin/' + binary)
            (directory / 'cgroup').write_text('0::/system.slice/' + unit + '\n')

        unrelated = proc_root / '205'
        (unrelated / 'fd').mkdir(parents=True)
        stat_tail = ['S', *(['0'] * 18), '999']
        (unrelated / 'stat').write_text(
            '205 (python3) ' + ' '.join(stat_tail) + '\n')
        (unrelated / 'cmdline').write_bytes(b'/usr/bin/python3\0unrelated-worker\0')
        (unrelated / 'fd' / '7').symlink_to(disk)

        def runner(args, **_):
            unit = args[2]
            return type('Result', (), {
                'returncode': 0,
                'stdout': f'ActiveState=active\nMainPID={units[unit][0]}\n',
                'stderr': '',
            })()

        with self.assertRaisesRegex(recovery.Blocked, 'untracked process references lab'):
            recovery.process_evidence(
                self.root, LAB, runner=runner, proc_root=proc_root)


if __name__ == "__main__":
    unittest.main()
