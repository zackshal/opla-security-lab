import importlib.util
from pathlib import Path
import sys
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
    def test_management_allows_replies_but_blocks_unsolicited_input(self):
        management = GOOD.replace('priority -20;', 'priority -19;').replace(
            f'        iifname "{BRIDGE}" udp dport 67 accept\n', '')
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=0, stdout=management, stderr='')):
            self.assertTrue(mod.verify_nft_before_network_cleanup(TABLE, BRIDGE, management=True))
        broken = management.replace(f'        iifname "{BRIDGE}" ct state established,related accept\n', '')
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=0, stdout=broken, stderr='')):
            with self.assertRaises(RuntimeError):
                mod.verify_nft_before_network_cleanup(TABLE, BRIDGE, management=True)

    def test_expected_rules_accepted(self):
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=0, stdout=GOOD, stderr='')):
            self.assertTrue(mod.verify_nft_before_network_cleanup(TABLE, BRIDGE))
    def test_foreign_rule_blocks(self):
        changed=GOOD.replace('    chain input {','    iifname \"eth0\" accept\n    chain input {')
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=0, stdout=changed, stderr='')):
            with self.assertRaises(RuntimeError): mod.verify_nft_before_network_cleanup(TABLE, BRIDGE)
    def test_probe_failure_blocks(self):
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=2, stdout='', stderr='permission denied')):
            with self.assertRaises(RuntimeError): mod.verify_nft_before_network_cleanup(TABLE, BRIDGE)
    def test_missing_table_allowed(self):
        with patch.object(mod, 'call', return_value=SimpleNamespace(returncode=1, stdout='', stderr='No such file or directory')):
            self.assertFalse(mod.verify_nft_before_network_cleanup(TABLE, BRIDGE))
    def test_lab_stop_does_not_stop_shared_monitoring(self):
        mk=(ROOT/'Makefile').read_text()
        recipe=mk.split('lab-stop:\n',1)[1].split('\nlab-infra-status:',1)[0]
        self.assertNotIn('monitoring-stop',recipe)
