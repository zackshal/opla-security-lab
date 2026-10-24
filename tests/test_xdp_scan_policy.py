import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('xdp_scan_policy', ROOT/'xdp/scan-policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
source_spec = importlib.util.spec_from_file_location('xdp_source_map', ROOT/'bin/source-map.py')
source_map = importlib.util.module_from_spec(source_spec)
source_spec.loader.exec_module(source_map)
sys.path.insert(0, str(ROOT/'xdp'))
import collect

class PolicyTests(unittest.TestCase):
    def test_source_map_reports_ttl_from_new_value(self):
        blob = bytearray(56)
        blob[24:32] = (40_000_000_000).to_bytes(8, sys.byteorder)
        blob[48:52] = (8).to_bytes(4, sys.byteorder)
        row = {'key': ['0x64','0x40','0x00','0x02'], 'value': [hex(x) for x in blob]}
        data = source_map.decode(row, 10_000_000_000)
        self.assertEqual(data['scan_distinct_ports'], 8)
        self.assertEqual(data['scan_block_remaining_seconds'], 30)
        self.assertEqual(source_map.decode(row, 50_000_000_000)['scan_block_remaining_seconds'], 0)

    def test_ipv4_trust_keeps_network_order_and_mode_native_order(self):
        blob = policy.encode('block', ['100.64.0.1', '100.64.0.4'])
        self.assertEqual(blob, struct.pack('=I', 2) + bytes([100,64,0,1,100,64,0,4]))

    def test_block_requires_two_distinct_trusted_sources(self):
        for addresses in ([], ['100.64.0.1'], ['100.64.0.1']*2):
            with self.assertRaises(ValueError):
                policy.encode('block', addresses)

    def test_invalid_sources_and_modes_rejected(self):
        for address in ('0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', 'invalid'):
            with self.assertRaises(ValueError):
                policy.encode('observe', [address, '100.64.0.4'])
        with self.assertRaises(ValueError):
            policy.encode('something', [])

    def test_off_needs_no_trust(self):
        self.assertEqual(policy.encode('off', []), bytes(12))

    def test_collector_reads_new_percpu_counters_and_policy(self):
        replies = [[{'xdp': {'attached': 'generic', 'prog': {'id': 4}}}], {'id': 4},
                   [{'key': 5, 'values': [{'value': 1}, {'value': 2}]},
                    {'key': 6, 'values': [{'value': 3}, {'value': 4}]}],
                   [{'key': ['0x00']*4, 'value': [hex(x) for x in policy.encode('block', ['100.64.0.1','100.64.0.4'])]}]]
        with patch.object(collect, 'run', side_effect=replies):
            data = collect.snapshot()
        self.assertEqual((data['xdp_scan_events'], data['xdp_scan_drop'], data['xdp_scan_mode']), (3,7,2))

    def test_empty_policy_map_means_off(self):
        replies = [[{'xdp': {'attached': 'generic', 'prog': {'id': 4}}}], {'id': 4},
                   [{'key': 5, 'value': 0}], []]
        with patch.object(collect, 'run', side_effect=replies):
            self.assertEqual(collect.snapshot()['xdp_scan_mode'], 0)

    def test_policy_map_abi_mismatch_prevents_update(self):
        with patch.object(sys, 'argv', ['policy', '--mode', 'off']), \
             patch.object(policy.subprocess, 'check_output', return_value='{"type":"array","key":4,"value":12,"max_entries":1}'), \
             patch.object(policy.subprocess, 'run') as update:
            with self.assertRaises(SystemExit) as failure:
                policy.main()
        self.assertEqual(failure.exception.code, 1)
        update.assert_not_called()
