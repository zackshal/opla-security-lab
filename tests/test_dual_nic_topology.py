"""Offline contract tests for the built-in dual-NIC academic topology."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DualNicTopologyTests(unittest.TestCase):
    def test_create_path_declares_data_and_management_resources(self):
        source = (ROOT / 'bin/create-lab.sh').read_text(encoding='utf-8')
        for field in ('MGMT_BRIDGE', 'MGMT_SUBNET', 'MGMT_GW',
                      'ATTACKER_MGMT_IP', 'VICTIM_MGMT_IP', 'CLIENT_MGMT_IP'):
            self.assertIn(field, source)
        self.assertIn('id=n0', source)
        self.assertIn('id=n1', source)
        self.assertIn('set-name: ens3', source)
        self.assertIn('set-name: ens4', source)
        self.assertIn('opla_mgmt_', source)
        self.assertIn('OPLA_EXCLUDE_BRIDGE="$BRIDGE"', source)

    def test_resume_path_requires_both_tap_sets_and_two_nics(self):
        source = (ROOT / 'bin/vm-disk.py').read_text(encoding='utf-8')
        self.assertIn("data['MGMT_BRIDGE']", source)
        self.assertIn('id=n0', source)
        self.assertIn('id=n1', source)
        self.assertIn('"management_tap"', (ROOT / 'bin/opla-registry.py').read_text(encoding='utf-8'))

    def test_ssh_transport_resolves_data_identity_to_management_address(self):
        source = (ROOT / 'xdp/lib.sh').read_text(encoding='utf-8')
        self.assertIn('SSH_IP', source)
        state = (ROOT / 'bin/state.py').read_text(encoding='utf-8')
        self.assertIn('ATTACKER_MGMT_IP', state)
        self.assertIn('VICTIM_MGMT_IP', state)
        self.assertIn('CLIENT_MGMT_IP', state)


if __name__ == '__main__':
    unittest.main()
