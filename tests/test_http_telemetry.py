import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('http_collect', Path(__file__).resolve().parents[1]/'xdp/collect.py')
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)


def record(status=200, limited='PASSED'):
    return json.dumps({'status': status, 'limit_req': limited}).encode()+b'\n'


class HttpTelemetryTests(unittest.TestCase):
    def test_incremental_read_partial_line_and_invalid_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            log = p/'access.jsonl'; state = p/'state'
            log.write_bytes(record()+record(429, 'REJECTED')+b'bad json\n'+b'{"status":503')
            a = collect.http_snapshot(log, state)
            self.assertEqual(a['http_requests'], 2)
            self.assertEqual(a['http_limited'], 1)
            self.assertEqual(a['http_parse_errors'], 1)
            self.assertEqual(collect.http_snapshot(log, state), a)
            with log.open('ab') as stream:
                stream.write(b'}\n')
            b = collect.http_snapshot(log, state)
            self.assertEqual(b['http_requests'], 3)
            self.assertEqual(b['http_5xx'], 1)

    def test_rotation_keeps_counts_and_reads_new_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); log = p/'access.jsonl'; state = p/'state'
            log.write_bytes(record())
            collect.http_snapshot(log, state)
            log.rename(p/'access.jsonl.1')
            log.write_bytes(record(429, 'REJECTED'))
            b = collect.http_snapshot(log, state)
            self.assertEqual(b['http_requests'], 2)
            self.assertEqual(b['http_limited'], 1)

    def test_missing_log_is_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            self.assertEqual(collect.http_snapshot(p/'missing', p/'state')['http_available'], 0)

    def test_local_probe_failure_is_reported_without_hiding_xdp(self):
        from unittest.mock import patch
        with patch.object(collect.http.client, 'HTTPConnection') as factory:
            factory.return_value.request.side_effect = ConnectionRefusedError()
            result = collect.http_probe()
            self.assertEqual(result['http_up'], 0)
            self.assertEqual(result['http_status'], 0)
            factory.return_value.close.assert_called_once()

    def test_rate_limit_response_is_not_successful_health_check(self):
        from unittest.mock import patch
        with patch.object(collect.http.client, 'HTTPConnection') as factory:
            factory.return_value.getresponse.return_value.status = 429
            result = collect.http_probe()
            self.assertEqual(result['http_status'], 429)
            self.assertEqual(result['http_up'], 0)
