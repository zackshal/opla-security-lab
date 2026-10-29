"""Fault-injection contract tests: no host QEMU/network/Docker operations.

These tests exercise the coordinator with substituted probes and operations.
They do not certify actual ownership verification on a Linux host.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'opla_v596_active_faults', ROOT / 'bin' / 'opla-active-creation-recover.py'
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
LAB = 'lab-Test123'
CONFIRM = 'RECOVER-CREATION:' + LAB


class ActiveRecoveryFaultTests(unittest.TestCase):
    def exercise(self, audit, evidence, stop, offline):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Only host root ownership and journal IO are mocked. No real mutation.
            with patch.object(mod.prune, 'safe_root', side_effect=lambda value: Path(value)), \
                 patch.object(mod.rollback, 'lock_is_safe', return_value=True), \
                 patch.object(mod.prune, 'write_journal') as journal:
                return mod.locked_recover(root, LAB, CONFIRM, audit=audit,
                                          evidence=evidence, stop=stop, offline=offline)

    def test_qmp_refusal_never_reaches_offline_cleanup(self):
        events = []
        def stop(*_):
            events.append('stop')
            raise RuntimeError('QMP timeout')
        with self.assertRaisesRegex(RuntimeError, 'QMP timeout'):
            self.exercise(lambda *_: events.append('audit'),
                          lambda *_: events.append('evidence'), stop,
                          lambda *_: events.append('offline'))
        self.assertEqual(events, ['audit', 'evidence', 'audit', 'evidence', 'stop'])

    def test_open_qcow2_blocks_before_host_mutation(self):
        events = []
        def evidence(*_):
            events.append('evidence')
            raise mod.Blocked('untracked process references lab disk.qcow2')
        with self.assertRaisesRegex(mod.Blocked, 'disk.qcow2'):
            self.exercise(lambda *_: events.append('audit'), evidence,
                          lambda *_: events.append('stop'),
                          lambda *_: events.append('offline'))
        self.assertEqual(events, ['audit', 'evidence'])

    def test_foreign_tap_blocks_before_host_mutation(self):
        events = []
        def audit(*_):
            events.append('audit')
            raise mod.Blocked('TAP master differs')
        with self.assertRaisesRegex(mod.Blocked, 'TAP'):
            self.exercise(audit, lambda *_: events.append('evidence'),
                          lambda *_: events.append('stop'),
                          lambda *_: events.append('offline'))
        self.assertEqual(events, ['audit'])

    def test_foreign_nft_rule_blocks_on_second_preflight(self):
        events = []
        def audit(*_):
            events.append('audit')
            if events.count('audit') == 2:
                raise mod.Blocked('nft policy mismatch')
        with self.assertRaisesRegex(mod.Blocked, 'nft'):
            self.exercise(audit, lambda *_: events.append('evidence'),
                          lambda *_: events.append('stop'),
                          lambda *_: events.append('offline'))
        self.assertEqual(events, ['audit', 'evidence', 'audit'])

    def test_foreign_management_nft_rule_blocks_before_stop(self):
        events = []
        def verify_policies(*_):
            events.append('policies')
            raise mod.Blocked('management nft policy mismatch')
        with self.assertRaisesRegex(mod.Blocked, 'management nft'):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                with patch.object(mod.prune, 'safe_root', side_effect=lambda value: Path(value)), \
                     patch.object(mod.rollback, 'lock_is_safe', return_value=True), \
                     patch.object(mod.prune, 'write_journal'):
                    mod.locked_recover(
                        root, LAB, CONFIRM,
                        audit=lambda *_: events.append('audit'),
                        evidence=lambda *_: events.append('evidence'),
                        stop=lambda *_: events.append('stop'),
                        offline=lambda *_: events.append('offline'),
                        verify_policies=verify_policies,
                    )
        self.assertEqual(events, ['audit', 'evidence', 'audit', 'evidence', 'policies'])

    def test_default_stop_checks_both_nft_policies_before_clean_stop(self):
        events = []
        state = {'LAB_ID': LAB, 'BRIDGE': 'br-op1', 'MGMT_BRIDGE': 'br-op2'}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.object(mod.prune, 'safe_root', side_effect=lambda value: Path(value)), \
                 patch.object(mod.rollback, 'lock_is_safe', return_value=True), \
                 patch.object(mod.prune, 'write_journal'), \
                 patch.object(mod.lifecycle, 'load', return_value=state), \
                 patch.object(mod.lifecycle, 'verify_lab_nft_policies',
                              side_effect=lambda value: events.append(('policies', value))), \
                 patch.object(mod.lifecycle, 'clean_stop',
                              side_effect=lambda labdir, value: events.append(('stop', value))):
                result = mod.locked_recover(
                    root, LAB, CONFIRM,
                    audit=lambda *_: events.append('audit'),
                    evidence=lambda *_: events.append('evidence'),
                    offline=lambda *_: {'fixture': True},
                )
        self.assertEqual(events, [
            'audit', 'evidence', 'audit', 'evidence',
            ('policies', state), ('stop', state), 'evidence',
        ])
        self.assertEqual(result['status'], 'completed')

    def test_retry_after_partial_stop_rechecks_before_cleanup(self):
        events = []
        attempts = [0]
        def stop(*_):
            events.append('stop')
            attempts[0] += 1
            if attempts[0] == 1:
                raise RuntimeError('DHCP stop failed')
        def audit(*_): events.append('audit')
        def evidence(*_): events.append('evidence')
        def offline(*_):
            events.append('offline')
            return {'offline': True}
        with self.assertRaisesRegex(RuntimeError, 'DHCP stop failed'):
            self.exercise(audit, evidence, stop, offline)
        self.assertNotIn('offline', events)
        events.clear()
        result = self.exercise(audit, evidence, stop, offline)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(events, ['audit', 'evidence', 'audit', 'evidence',
                                  'stop', 'evidence', 'offline'])


if __name__ == '__main__':
    unittest.main()
