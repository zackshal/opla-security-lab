import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


scan = module('opla_scan_test', ROOT / 'security/scan/detector.py')
collect = module('scan_collect_test', ROOT / 'xdp/collect.py')


def packet(port=22, flags=2, vlan=0, options=0, fragment=0):
    eth = b'\x00' * 12 + struct.pack('!H', 0x8100 if vlan else 0x0800)
    tags = b''.join(struct.pack('!HH', 1, 0x8100 if x < vlan - 1 else 0x0800) for x in range(vlan))
    ip = bytearray(20 + options)
    ip[0] = 0x40 | ((20 + options) // 4)
    struct.pack_into('!H', ip, 2, len(ip) + 20)
    struct.pack_into('!H', ip, 6, fragment)
    ip[9] = 6
    ip[12:16] = socket.inet_aton('100.64.0.2')
    ip[16:20] = socket.inet_aton('100.64.0.3')
    tcp = bytearray(20)
    struct.pack_into('!HH', tcp, 0, 40000, port)
    tcp[12] = 0x50
    tcp[13] = flags
    return eth + tags + ip + tcp


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.d = scan.Detector('100.64.0.3')

    def observe(self, port, now=0, source='100.64.0.2'):
        return self.d.observe(source, '100.64.0.3', port, now)

    def test_three_port_scan_is_below_threshold(self):
        for port in (22, 80, 443):
            self.assertIsNone(self.observe(port))
        self.assertEqual(self.d.snapshot(1)['scan_active'], 0)

    def test_eighth_distinct_port_crosses_threshold(self):
        for port in range(1, 8):
            self.assertIsNone(self.observe(port))
        event = self.observe(8)
        self.assertEqual(event['distinct_ports'], 8)
        self.assertEqual(event['source_ip'], '100.64.0.2')
        self.assertEqual(event['action'], 'alert')
        self.assertEqual(self.d.snapshot(1)['scan_active'], 1)

    def test_retransmissions_and_web_requests_are_not_distinct_ports(self):
        for i in range(1000):
            self.assertIsNone(self.observe(80, now=i / 100))
        self.assertEqual(self.d.counters['alerts'], 0)

    def test_one_event_during_continuous_scan(self):
        events = [self.observe(port, now=port / 100) for port in range(1, 200)]
        self.assertEqual(sum(x is not None for x in events), 1)
        self.assertLessEqual(len(next(iter(self.d.pairs.values()))['ports']), 64)

    def test_window_boundary_expires_and_rearms(self):
        for port in range(8):
            self.observe(port, now=0)
        self.assertEqual(self.d.snapshot(59.999)['scan_active'], 1)
        self.assertEqual(self.d.snapshot(60)['scan_active'], 0)
        for port in range(8):
            self.observe(port, now=61)
        self.assertEqual(self.d.counters['alerts'], 2)

    def test_ports_outside_window_do_not_accumulate(self):
        for port in range(10):
            self.observe(port, now=port * 61)
        self.assertEqual(self.d.counters['alerts'], 0)

    def test_different_sources_are_not_combined(self):
        for port in range(4):
            self.observe(port, source='100.64.0.2')
            self.observe(port + 4, source='100.64.0.4')
        self.assertEqual(self.d.counters['alerts'], 0)

    def test_other_destination_and_local_source_are_ignored(self):
        self.assertIsNone(self.d.observe('100.64.0.2', '100.64.0.4', 80, 0))
        self.assertIsNone(self.d.observe('100.64.0.3', '100.64.0.3', 80, 0))
        self.assertEqual(len(self.d.pairs), 0)

    def test_source_state_is_bounded_and_pressure_visible(self):
        d = scan.Detector('100.64.0.3', max_pairs=2)
        for source in ('100.64.0.1', '100.64.0.2', '100.64.0.4'):
            d.observe(source, '100.64.0.3', 80, 0)
        self.assertEqual(len(d.pairs), 2)
        self.assertEqual(d.snapshot(1)['scan_evictions'], 1)

    def test_counters_persist_but_window_is_not_fabricated_after_restart(self):
        for port in range(8):
            self.observe(port)
        restarted = scan.Detector('100.64.0.3', counters=self.d.counters)
        self.assertEqual(restarted.snapshot(1)['scan_alerts'], 1)
        self.assertEqual(restarted.snapshot(1)['scan_active'], 0)

    def test_invalid_bounds_are_rejected(self):
        with self.assertRaises(ValueError):
            scan.Detector('100.64.0.3', threshold=65)


class ParserTests(unittest.TestCase):
    def test_plain_vlan_double_vlan_and_ip_options(self):
        for tags in range(3):
            for options in (0, 4, 40):
                self.assertEqual(scan.parse_syn(packet(443, vlan=tags, options=options)),
                                 ('100.64.0.2', '100.64.0.3', 443))

    def test_truncated_packet_every_prefix(self):
        original = packet()
        for length in range(len(original)):
            self.assertIsNone(scan.parse_syn(original[:length]))

    def test_ack_synack_fin_rst_and_fragments_ignored(self):
        for flags in (0, 16, 18, 1, 4, 3, 6):
            self.assertIsNone(scan.parse_syn(packet(flags=flags)))
        for fragment in (0x2000, 1):
            self.assertIsNone(scan.parse_syn(packet(fragment=fragment)))

    def test_non_ipv4_and_third_vlan_are_ignored(self):
        data = bytearray(packet())
        data[12:14] = b'\x86\xdd'
        self.assertIsNone(scan.parse_syn(data))
        self.assertIsNone(scan.parse_syn(packet(vlan=3)))

    def test_invalid_ihl_and_tcp_header_are_ignored(self):
        data = bytearray(packet())
        data[14] = 0x44
        self.assertIsNone(scan.parse_syn(data))
        data = bytearray(packet())
        data[14 + 20 + 12] = 0x40
        self.assertIsNone(scan.parse_syn(data))


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.status = self.root / 'status.json'
        self.marker = self.root / 'enabled'
        self.counters = self.root / 'counters.json'
        self.marker.write_text('enabled')

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self, now=10):
        return collect.scan_snapshot(self.status, self.marker, self.counters, now)

    def test_missing_sensor_reports_unavailable(self):
        data = self.snapshot()
        self.assertEqual((data['scan_enabled'], data['scan_up']), (1, 0))

    def test_disabled_sensor_does_not_claim_running(self):
        self.marker.unlink()
        self.assertEqual(self.snapshot()['scan_enabled'], 0)

    def test_fresh_stale_and_future_heartbeat(self):
        d = scan.Detector('100.64.0.3')
        for port in range(8):
            d.observe('100.64.0.2', '100.64.0.3', port, 9)
        scan.atomic_json(self.status, d.snapshot(10))
        self.assertEqual(self.snapshot()['scan_up'], 1)
        self.assertEqual(self.snapshot()['scan_active'], 1)
        self.assertEqual(self.snapshot(now=21)['scan_up'], 0)
        self.assertEqual(self.snapshot(now=9)['scan_up'], 0)

    def test_malformed_json_is_unavailable_not_false_healthy(self):
        self.status.write_text('{')
        self.assertEqual(self.snapshot()['scan_up'], 0)

    def test_persistent_counters_survive_missing_runtime_status(self):
        scan.atomic_json(self.counters, dict(alerts=4, capture_drops=3, evictions=2))
        data = self.snapshot()
        self.assertEqual((data['scan_alerts'], data['scan_capture_drops'], data['scan_evictions']), (4, 3, 2))


if __name__ == '__main__':
    unittest.main()
