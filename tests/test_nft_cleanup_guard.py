import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
spec = importlib.util.spec_from_file_location('opla_lifecycle_guard', ROOT/'bin/lab-lifecycle.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

TABLE = 'opla_lab_Ab1234'
BRIDGE = 'br-op1234'
GOOD = f"""table inet {TABLE} {{
    chain forward {{
        type filter hook forward priority -20; policy accept;
        iifname \"{BRIDGE}\" oifname != \"{BRIDGE}\" drop
        oifname \"{BRIDGE}\" iifname != \"{BRIDGE}\" drop
    }}
    chain input {{
        type filter hook input priority -20; policy accept;
        iifname \"{BRIDGE}\" ct state established,related accept
        iifname \"{BRIDGE}\" udp dport 67 accept
        iifname \"{BRIDGE}\" drop
    }}
}}"""

class GuardTests(unittest.TestCase):
    LAB_STATE = {
        'LAB_ID': 'lab-ABCD', 'BRIDGE': 'br-op0', 'MGMT_BRIDGE': 'br-op1',
        'GW': '100.64.0.1', 'MGMT_GW': '100.64.0.9', 'VICTIM_IP': '100.64.0.3',
    }

    @staticmethod
    def _expected_data():
        return GOOD.replace(TABLE, 'opla_lab_ABCD').replace(BRIDGE, 'br-op0')

    @staticmethod
    def _expected_management():
        return (GOOD.replace(TABLE, 'opla_mgmt_lab_ABCD').replace(BRIDGE, 'br-op1')
                .replace('priority -20;', 'priority -19;')
                .replace(f'        iifname "br-op1" udp dport 67 accept\n', ''))

    def test_start_preflight_rejects_foreign_data_nft_policy(self):
        foreign = self._expected_data().replace(
            'iifname "br-op0" oifname != "br-op0" drop',
            'iifname "br-op0" accept',
        )
        with patch.object(mod, 'active', return_value=False), \
                patch.object(mod, 'call', return_value=SimpleNamespace(
                    returncode=0, stdout=foreign, stderr='')) as call:
            with self.assertRaisesRegex(RuntimeError, 'differs from expected'):
                mod.preflight(Path('/tmp/lab-ABCD'), self.LAB_STATE)
        self.assertEqual(call.call_args_list, [
            unittest.mock.call('nft', 'list', 'table', 'inet', 'opla_lab_ABCD', check=False),
        ])

    def test_start_preflight_rejects_foreign_management_nft_policy(self):
        foreign = self._expected_management().replace(
            'iifname "br-op1" drop', 'iifname "br-op1" accept',
        )
        responses = [
            SimpleNamespace(returncode=0, stdout=self._expected_data(), stderr=''),
            SimpleNamespace(returncode=0, stdout=foreign, stderr=''),
        ]
        with patch.object(mod, 'active', return_value=False), \
                patch.object(mod, 'call', side_effect=responses) as call:
            with self.assertRaisesRegex(RuntimeError, 'differs from expected'):
                mod.preflight(Path('/tmp/lab-ABCD'), self.LAB_STATE)
        self.assertEqual(call.call_count, 2)
        self.assertEqual(call.call_args_list[-1], unittest.mock.call(
            'nft', 'list', 'table', 'inet', 'opla_mgmt_lab_ABCD', check=False))

    def test_start_preflight_allows_only_expected_or_explicitly_absent_tables(self):
        expected = [self._expected_data(), self._expected_management()]
        missing = [SimpleNamespace(returncode=1, stdout='', stderr='No such file or directory')
                   for _ in range(2)]
        for responses in (expected, missing):
            with self.subTest(existing=responses is expected), \
                    patch.object(mod, 'call', side_effect=[
                        item if isinstance(item, SimpleNamespace) else SimpleNamespace(
                            returncode=0, stdout=item, stderr='') for item in responses
                    ]) as call:
                mod.verify_lab_nft_policies(self.LAB_STATE)
                self.assertEqual(call.call_count, 2)

    def test_prepare_network_creates_both_policies_when_explicitly_absent(self):
        missing = SimpleNamespace(returncode=1, stdout='', stderr='No such file or directory')
        def fake_call(*args, **_kwargs):
            if args[:3] == ('nft', 'list', 'table'):
                return missing
            if args[:3] == ('ip', '-4', 'route'):
                return SimpleNamespace(returncode=0, stdout='100.64.0.3 dev br-op0', stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp)
            (lab / 'dnsmasq.conf').write_text('# fixture\n', encoding='utf-8')
            with patch.object(mod, 'call', side_effect=fake_call) as call, \
                    patch.object(mod, 'interface', return_value=False), \
                    patch.object(mod, 'active', return_value=False):
                mod.prepare_network(lab, self.LAB_STATE)
        rule_installs = [item for item in call.call_args_list
                         if item.args[:3] == ('nft', '-f', '-')]
        self.assertEqual(len(rule_installs), 2)

    def test_start_rechecks_both_policies_before_creating_interfaces(self):
        foreign = self._expected_management().replace(
            'iifname "br-op1" drop', 'iifname "br-op1" accept',
        )
        with patch.object(mod, 'call', side_effect=[
                SimpleNamespace(returncode=1, stdout='', stderr='No such file or directory'),
                SimpleNamespace(returncode=0, stdout=foreign, stderr=''),
        ]), patch.object(mod, 'interface') as interface:
            with self.assertRaisesRegex(RuntimeError, 'differs from expected'):
                mod.prepare_network(Path('/tmp/lab-ABCD'), self.LAB_STATE)
        interface.assert_not_called()

    def test_start_rechecks_both_policies_after_network_setup_before_qemu(self):
        events = []
        def verify(_state, **_kwargs):
            events.append('policy')
            raise RuntimeError('nft policy changed during network setup')
        with patch.object(mod, 'preflight', side_effect=lambda *_: events.append('preflight')), \
                patch.object(mod, 'prepare_network', side_effect=lambda *_: events.append('network')), \
                patch.object(mod, 'verify_lab_nft_policies', side_effect=verify), \
                patch.object(mod, 'resume', side_effect=lambda *_: events.append('qemu')) as resume:
            with self.assertRaisesRegex(RuntimeError, 'changed during network setup'):
                mod.start_lab(Path('/tmp/lab-ABCD'), self.LAB_STATE)
        self.assertEqual(events, ['preflight', 'network', 'policy'])
        resume.assert_not_called()

    def test_start_checks_policy_immediately_before_qemu_resume(self):
        events = []
        with patch.object(mod, 'preflight', side_effect=lambda *_: events.append('preflight')), \
                patch.object(mod, 'prepare_network', side_effect=lambda *_: events.append('network')), \
                patch.object(mod, 'verify_lab_nft_policies', side_effect=lambda *_args, **_kwargs: events.append('policy')), \
                patch.object(mod, 'resume', side_effect=lambda *_: events.append('qemu')):
            mod.start_lab(Path('/tmp/lab-ABCD'), self.LAB_STATE)
        self.assertEqual(events, ['preflight', 'network', 'policy', 'qemu'])

    def test_final_start_gate_rejects_missing_data_or_management_table(self):
        expected = [self._expected_data(), self._expected_management()]
        missing = SimpleNamespace(returncode=1, stdout='', stderr='No such file or directory')
        for missing_index, missing_name in ((0, 'data'), (1, 'management')):
            responses = [SimpleNamespace(returncode=0, stdout=payload, stderr='')
                         for payload in expected]
            responses[missing_index] = missing
            with self.subTest(table=missing_name), \
                    patch.object(mod, 'preflight'), \
                    patch.object(mod, 'prepare_network'), \
                    patch.object(mod, 'call', side_effect=responses), \
                    patch.object(mod, 'resume') as resume:
                with self.assertRaisesRegex(RuntimeError, 'missing before VM resume'):
                    mod.start_lab(Path('/tmp/lab-ABCD'), self.LAB_STATE)
                resume.assert_not_called()

    def test_clean_stop_rechecks_management_policy_before_qmp(self):
        with patch.object(mod, 'verify_lab_nft_policies',
                          side_effect=[None, RuntimeError('management nft policy mismatch')]) as policy, \
             patch.object(mod, 'active') as active, \
             patch.object(Path, 'is_socket', return_value=True), \
             patch.object(mod, 'QMP') as qmp:
            with self.assertRaisesRegex(RuntimeError, 'management nft policy mismatch'):
                mod.clean_stop(Path('/tmp/lab-ABCD'), self.LAB_STATE)
        self.assertEqual(policy.call_count, 2)
        self.assertTrue(all(call.args == (self.LAB_STATE,) for call in policy.call_args_list))
        active.assert_called()
        qmp.assert_not_called()

    def test_clean_stop_rechecks_policy_before_each_vm_power_request(self):
        calls = []
        policy = [None, None, None, RuntimeError('nft policy changed during stop')]

        class FakeQMP:
            def __init__(self, path, timeout):
                self.path = path
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def call(self, command):
                calls.append((self.path.name, command))

        with patch.object(mod, 'verify_lab_nft_policies', side_effect=policy) as verify, \
                patch.object(mod, 'active', return_value=True), \
                patch.object(Path, 'is_socket', return_value=True), \
                patch.object(mod, 'QMP', FakeQMP):
            with self.assertRaisesRegex(RuntimeError, 'changed during stop'):
                mod.clean_stop(Path('/tmp/lab-ABCD'), self.LAB_STATE)

        self.assertEqual(verify.call_count, 4)
        expected_stopped = list(mod.VMS)[:2]
        self.assertEqual(calls, [
            (f'{vm}-qmp.sock', 'system_powerdown') for vm in expected_stopped
        ])

    def test_legacy_management_taps_removed_only_from_owned_bridge(self):
        from tempfile import TemporaryDirectory
        state = {'LAB_ID': 'lab-ABCD', 'BRIDGE': 'br-op0', 'MGMT_BRIDGE': 'br-op1',
                 'GW': '100.64.0.1', 'MGMT_GW': '100.64.0.9'}
        def fake_call(*args, **kwargs):
            return SimpleNamespace(stdout='master br-op1 state DOWN', returncode=0)
        with TemporaryDirectory() as temp, patch.object(mod, 'call', side_effect=fake_call) as call, \
                patch.object(mod, 'active', return_value=False), \
                patch.object(mod, 'verify_nft_policy', return_value=False), \
                patch.object(mod, 'interface', side_effect=lambda name: name in {'op0A', 'op0V', 'op0C'}):
            mod.remove_network(Path(temp), state)
            for name in ('op0A', 'op0V', 'op0C'):
                call.assert_any_call('ip', 'link', 'delete', 'dev', name)

    def test_management_allows_replies_but_blocks_unsolicited_input(self):
        management = GOOD.replace('priority -20;', 'priority -19;').replace(
            f'        iifname "{BRIDGE}" udp dport 67 accept\n', '')
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=0, stdout=management, stderr='')):
            self.assertTrue(mod.verify_nft_policy(TABLE, BRIDGE, management=True))
        broken = management.replace(f'        iifname "{BRIDGE}" ct state established,related accept\n', '')
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=0, stdout=broken, stderr='')):
            with self.assertRaises(RuntimeError):
                mod.verify_nft_policy(TABLE, BRIDGE, management=True)

    def test_expected_rules_accepted(self):
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=0, stdout=GOOD, stderr='')):
            self.assertTrue(mod.verify_nft_policy(TABLE, BRIDGE))
    def test_foreign_rule_blocks(self):
        changed=GOOD.replace('    chain input {','    iifname \"eth0\" accept\n    chain input {')
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=0, stdout=changed, stderr='')):
            with self.assertRaises(RuntimeError): mod.verify_nft_policy(TABLE, BRIDGE)
    def test_probe_failure_blocks(self):
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=2, stdout='', stderr='permission denied')):
            with self.assertRaises(RuntimeError): mod.verify_nft_policy(TABLE, BRIDGE)
    def test_missing_table_allowed(self):
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=1, stdout='', stderr='No such file or directory')):
            self.assertFalse(mod.verify_nft_policy(TABLE, BRIDGE))
    def test_lab_stop_does_not_stop_shared_monitoring(self):
        mk=(ROOT/'Makefile').read_text()
        recipe=mk.split('lab-stop:\n',1)[1].split('\nlab-infra-status:',1)[0]
        self.assertNotIn('monitoring-stop',recipe)
