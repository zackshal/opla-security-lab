import importlib.util
import json
import math
from pathlib import Path
import stat
import tempfile
import struct
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('xdp_scan_policy', ROOT/'xdp/scan-policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
attached_program_id = policy.attached_program_id
source_spec = importlib.util.spec_from_file_location('xdp_source_map', ROOT/'bin/source-map.py')
source_map = importlib.util.module_from_spec(source_spec)
source_spec.loader.exec_module(source_map)
sys.path.insert(0, str(ROOT/'xdp'))
import collect

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.lock_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.lock_dir.cleanup)
        self.lock_path_patch = patch.object(policy, 'LOCK_PATH', Path(self.lock_dir.name) / 'opla-xdp.lock')
        self.lock_path_patch.start()
        self.addCleanup(self.lock_path_patch.stop)
        receipt = {'schema_version': 2, 'program_id': 9, 'program_tag': 'prog-tag',
                   'program_map_ids': [2, 3, 4],
                   'maps': {'syn_windows': {'id': 2, 'type': 'lru_hash'},
                            'xdp_stats': {'id': 3, 'type': 'percpu_array'},
                            'xdp_policy': {'id': 4, 'type': 'hash'}}}
        self.receipt_patch = patch.object(policy, 'load_receipt', return_value=receipt)
        self.receipt_patch.start()
        self.addCleanup(self.receipt_patch.stop)
        self.program_patch = patch.object(policy, 'pinned_program',
                                          return_value={'id': 9, 'tag': 'prog-tag',
                                                        'map_ids': [2, 3, 4]})
        self.program_patch.start()
        self.addCleanup(self.program_patch.stop)
        self.map_inventory_patch = patch.object(
            policy, 'pinned_map_inventory',
            return_value={'syn_windows': {'id': 2, 'type': 'lru_hash'},
                          'xdp_stats': {'id': 3, 'type': 'percpu_array'},
                          'xdp_policy': {'id': 4, 'type': 'hash'}})
        self.map_inventory_patch.start()
        self.addCleanup(self.map_inventory_patch.stop)
        self.attachment_patch = patch.object(policy, 'attached_program_id', return_value=9)
        self.attachment_patch.start()
        self.addCleanup(self.attachment_patch.stop)

    def test_syn_window_source_uses_bounded_lru_map(self):
        source = (ROOT / 'xdp/xdp_ddos_protect.c').read_text()
        self.assertIn('__uint(type, BPF_MAP_TYPE_LRU_HASH);', source)
        self.assertIn('kernel-managed eviction', source)

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

    def test_attachment_identity_accepts_iproute2_list_form(self):
        payload = '[{"ifname":"ens3","xdp":{"attached":["drv"],"prog_id":19}}]'
        with patch.object(policy.subprocess, 'check_output', return_value=payload):
            self.assertEqual(attached_program_id(), 19)

    def test_attachment_identity_accepts_legacy_scalar_form(self):
        payload = '[{"ifname":"ens3","xdp":{"attached":"native","prog":{"id":19}}}]'
        with patch.object(policy.subprocess, 'check_output', return_value=payload):
            self.assertEqual(attached_program_id(), 19)

    def test_attachment_identity_accepts_iproute2_structured_attachment_records(self):
        payload = json.dumps([{
            'ifname': 'ens3',
            'xdp': {
                'mode': 4,
                'attached': [
                    {'mode': 1, 'prog': {'id': 19, 'tag': 'drv-tag'}},
                    {'mode': 2, 'prog': {'id': 23, 'tag': 'skb-tag'}},
                ],
            },
        }])
        with patch.object(policy.subprocess, 'check_output', return_value=payload):
            self.assertEqual(attached_program_id(), [19, 23])

    def test_multi_mode_identity_must_include_the_pinned_opla_program(self):
        map_info = {'id': 4, 'type': 'hash', 'bytes_key': 4,
                    'bytes_value': 12, 'max_entries': 1}
        policy.validate_policy_map_identity(
            map_info, policy.load_receipt(), policy.pinned_program(),
            policy.pinned_map_inventory(), [23, 9],
        )
        with self.assertRaisesRegex(ValueError, 'pinned OPLA program'):
            policy.validate_policy_map_identity(
                map_info, policy.load_receipt(), policy.pinned_program(),
                policy.pinned_map_inventory(), [23, 42],
            )

    def test_attachment_identity_rejects_malformed_or_unknown_modes(self):
        for attached in ([], ['mystery'], ['drv', 3], {'drv': True}, None):
            payload = json.dumps([{
                'ifname': 'ens3',
                'xdp': {'attached': attached, 'prog_id': 19},
            }])
            with self.subTest(attached=attached), \
                 patch.object(policy.subprocess, 'check_output', return_value=payload), \
                 self.assertRaisesRegex(ValueError, 'XDP attachment'):
                attached_program_id()

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
             patch.object(policy.subprocess, 'check_output', return_value='{"type":"array","bytes_key":4,"bytes_value":12,"max_entries":1}'), \
             patch.object(policy.subprocess, 'run') as update:
            with self.assertRaises(SystemExit) as failure:
                policy.main()
        self.assertEqual(failure.exception.code, 1)
        update.assert_not_called()

    def test_actual_bpftool_header_allows_policy_update(self):
        with patch.object(sys, 'argv', ['policy', '--mode', 'observe', '--trusted-source', '100.64.0.1', '--trusted-source', '100.64.0.4']), \
             patch.object(policy.subprocess, 'check_output', return_value='{"id":4,"type":"hash","bytes_key":4,"bytes_value":12,"max_entries":1}'), \
             patch.object(policy.subprocess, 'run') as update:
            policy.main()
        command = update.call_args.args[0]
        offset = command.index('value') + 2
        self.assertEqual(bytes.fromhex(''.join(command[offset:])), policy.encode('observe', ['100.64.0.1','100.64.0.4']))

    def test_missing_bpftool_size_fields_prevent_update(self):
        with patch.object(sys, 'argv', ['policy', '--mode', 'off']), \
             patch.object(policy.subprocess, 'check_output', return_value='{"type":"hash","max_entries":1}'), \
             patch.object(policy.subprocess, 'run') as update:
            with self.assertRaises(SystemExit):
                policy.main()
        update.assert_not_called()

    def test_empty_or_multiple_map_metadata_records_prevent_update(self):
        for payload in ('[]', '[{"type":"hash","bytes_key":4,"bytes_value":12,"max_entries":1},'
                        '{"type":"hash","bytes_key":4,"bytes_value":12,"max_entries":1}]'):
            with self.subTest(payload=payload), \
                 patch.object(sys, 'argv', ['policy', '--mode', 'off']), \
                 patch.object(policy.subprocess, 'check_output', return_value=payload), \
                 patch.object(policy.subprocess, 'run') as update:
                with self.assertRaises(SystemExit) as failure:
                    policy.main()
                self.assertEqual(failure.exception.code, 1)
                update.assert_not_called()

    def test_boolean_map_abi_size_is_not_accepted_as_integer(self):
        payload = '{"type":"hash","bytes_key":4,"bytes_value":12,"max_entries":true}'
        with patch.object(sys, 'argv', ['policy', '--mode', 'off']), \
             patch.object(policy.subprocess, 'check_output', return_value=payload), \
             patch.object(policy.subprocess, 'run') as update:
            with self.assertRaises(SystemExit) as failure:
                policy.main()
        self.assertEqual(failure.exception.code, 1)
        update.assert_not_called()

    def test_policy_update_requires_map_ids_referenced_by_program(self):
        map_info = {'id': 4, 'type': 'hash', 'bytes_key': 4,
                    'bytes_value': 12, 'max_entries': 1}
        receipt = policy.load_receipt()
        program = {'id': 9, 'tag': 'prog-tag', 'map_ids': [2, 3, 8]}
        with self.assertRaisesRegex(ValueError, 'map IDs'):
            policy.validate_policy_map_identity(map_info, receipt, program,
                                                policy.pinned_map_inventory(), 9)

    def test_policy_update_rejects_map_object_substitution(self):
        map_info = {'id': 44, 'type': 'hash', 'bytes_key': 4,
                    'bytes_value': 12, 'max_entries': 1}
        with self.assertRaisesRegex(ValueError, 'differs from load receipt'):
            policy.validate_policy_map_identity(map_info, policy.load_receipt(),
                                                policy.pinned_program(),
                                                policy.pinned_map_inventory(), 9)

    def test_legacy_receipt_is_accepted_only_after_live_map_identity_match(self):
        receipt = dict(policy.load_receipt())
        receipt['schema_version'] = 1
        receipt.pop('program_map_ids')
        receipt.pop('maps')
        map_info = {'id': 4, 'type': 'hash', 'bytes_key': 4,
                    'bytes_value': 12, 'max_entries': 1}
        policy.validate_policy_map_identity(map_info, receipt, policy.pinned_program(),
                                            policy.pinned_map_inventory(), 9)
        foreign = policy.pinned_map_inventory()
        foreign['xdp_policy'] = {'id': 44, 'type': 'hash'}
        with self.assertRaisesRegex(ValueError, 'differ from the loaded'):
            policy.validate_policy_map_identity(map_info, receipt, policy.pinned_program(), foreign, 9)

    def test_policy_update_requires_interface_to_run_receipt_program(self):
        map_info = {'id': 4, 'type': 'hash', 'bytes_key': 4,
                    'bytes_value': 12, 'max_entries': 1}
        with self.assertRaisesRegex(ValueError, 'pinned OPLA program'):
            policy.validate_policy_map_identity(map_info, policy.load_receipt(),
                                                policy.pinned_program(),
                                                policy.pinned_map_inventory(), 42)

    def test_boolean_program_and_map_ids_are_not_integer_identity(self):
        map_info = {'id': 4, 'type': 'hash', 'bytes_key': 4,
                    'bytes_value': 12, 'max_entries': 1}
        receipt = policy.load_receipt()
        with self.assertRaisesRegex(ValueError, 'pinned OPLA program'):
            policy.validate_policy_map_identity(map_info, receipt,
                {'id': True, 'tag': 'prog-tag', 'map_ids': [2, 3, 4]},
                policy.pinned_map_inventory(), 1)
        bad_map_info = dict(map_info, id=True)
        with self.assertRaisesRegex(ValueError, 'scan-policy map'):
            policy.validate_policy_map_identity(bad_map_info, receipt,
                policy.pinned_program(), policy.pinned_map_inventory(), 9)

    def test_boolean_ids_in_transitional_receipt_are_rejected(self):
        map_info = {'id': 4, 'type': 'hash', 'bytes_key': 4,
                    'bytes_value': 12, 'max_entries': 1}
        receipt = dict(policy.load_receipt())
        receipt['schema_version'] = 1
        receipt['program_map_ids'] = [True, 3, 4]
        with self.assertRaisesRegex(ValueError, 'program map IDs'):
            policy.validate_policy_map_identity(map_info, receipt, policy.pinned_program(),
                                                policy.pinned_map_inventory(), 9)
        receipt = dict(policy.load_receipt())
        receipt['schema_version'] = 1
        receipt['maps'] = dict(receipt['maps'])
        receipt['maps']['syn_windows'] = {'id': True, 'type': 'lru_hash'}
        with self.assertRaisesRegex(ValueError, 'differs from load receipt'):
            policy.validate_policy_map_identity(map_info, receipt, policy.pinned_program(),
                                                policy.pinned_map_inventory(), 9)

    def test_root_owned_sticky_lock_directory_is_supported(self):
        info = type('Stat', (), {'st_mode': stat.S_IFDIR | 0o1777, 'st_uid': 0})()
        self.assertTrue(policy.safe_lock_directory(info, 0))
        self.assertFalse(policy.safe_lock_directory(info, 1000))
        unsafe = type('Stat', (), {'st_mode': stat.S_IFDIR | 0o0777, 'st_uid': 0})()
        self.assertFalse(policy.safe_lock_directory(unsafe, 0))
        private = type('Stat', (), {'st_mode': stat.S_IFDIR | 0o0755, 'st_uid': 1000})()
        self.assertTrue(policy.safe_lock_directory(private, 1000))

    def test_non_root_rejects_root_sticky_lock_dir_before_creating_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / 'lock'
            sticky_root = type('Stat', (), {'st_mode': stat.S_IFDIR | 0o1777,
                                            'st_uid': 0})()
            with patch.object(policy, 'LOCK_PATH', lock_path), \
                 patch.object(Path, 'lstat', return_value=sticky_root), \
                 patch.object(policy.os, 'geteuid', return_value=1000), \
                 patch.object(policy.os, 'open') as opener, \
                 self.assertRaisesRegex(ValueError, 'directory has unsafe'):
                with policy.policy_lock():
                    pass
            opener.assert_not_called()
            self.assertFalse(lock_path.exists())

    def test_load_receipt_rejects_duplicate_json_keys(self):
        self.receipt_patch.stop()
        with tempfile.TemporaryDirectory() as tmp:
            receipt_path = Path(tmp) / 'receipt.json'
            receipt_path.write_text('{"schema_version":2,"schema_version":1}')
            fake_info = type('Stat', (), {'st_mode': stat.S_IFREG | 0o600,
                                          'st_nlink': 1, 'st_uid': 0,
                                          'st_size': receipt_path.stat().st_size})()
            with patch.object(policy, 'LOAD_RECEIPT', receipt_path), \
                 patch.object(policy.os, 'fstat', return_value=fake_info), \
                 self.assertRaisesRegex(ValueError, 'duplicate'):
                policy.load_receipt()

    def test_lifecycle_lock_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'target'
            target.write_text('')
            lock = root / 'lock'
            with patch.object(policy, 'LOCK_PATH', lock):
                lock.symlink_to(target)
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    with policy.policy_lock():
                        pass
                lock.unlink()
                lock.write_text('')
                (root / 'alias').hardlink_to(lock)
                with self.assertRaisesRegex(ValueError, 'identity or permissions'):
                    with policy.policy_lock():
                        pass

    def test_bpftool_dispatch_receives_finite_timeout(self):
        with patch.object(sys, 'argv', ['policy', '--mode', 'off']), \
             patch.object(policy.subprocess, 'check_output', return_value='{"id":4,"type":"hash","bytes_key":4,"bytes_value":12,"max_entries":1}') as inspect, \
             patch.object(policy.subprocess, 'run') as update:
            policy.main(timeout=3.5)
        self.assertEqual(inspect.call_args.kwargs['timeout'], 3.5)
        self.assertEqual(update.call_args.kwargs['timeout'], 3.5)

    def test_invalid_bpftool_timeout_rejected_before_dispatch(self):
        for timeout in (True, 0, -1, math.nan, math.inf, '5'):
            with self.subTest(timeout=timeout), \
                 patch.object(sys, 'argv', ['policy', '--mode', 'off']), \
                 patch.object(policy.subprocess, 'check_output') as inspect:
                with self.assertRaises(SystemExit):
                    policy.main(timeout=timeout)
                inspect.assert_not_called()
