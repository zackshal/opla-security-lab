"""Fault injection at the service boundary; no host resources required."""
import unittest
from unittest.mock import Mock, patch

from tests.test_microservice_architecture_docs import CONTRACT, TRANSPORT


class TransportFaultTests(unittest.TestCase):
    def test_invalid_deadlines_rejected_before_socket(self):
        for value in (True, 0, -1, float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                TRANSPORT.JsonLineServiceClient('/tmp/test.sock', timeout=value)

    def test_truncated_multiple_and_oversized_frames_rejected(self):
        for chunks in ([b'{}', b''], [b'{}\n{}\n'], [b'x' * 257]):
            connection = Mock()
            connection.recv.side_effect = chunks
            with self.subTest(chunks=chunks), self.assertRaises(TRANSPORT.ServiceTransportError):
                TRANSPORT._read_frame(connection, 256, 1)

    def test_fragmented_frame_accepted(self):
        connection = Mock()
        connection.recv.side_effect = [b'{', b'}', b'\n']
        self.assertEqual(TRANSPORT._read_frame(connection, 256, 1), b'{}')

    def test_drip_feed_cannot_extend_deadline(self):
        connection = Mock()
        connection.recv.return_value = b'x'
        with patch.object(TRANSPORT.time, 'monotonic', side_effect=[0, 0.5, 1.1]):
            with self.assertRaises(TRANSPORT.ServiceTransportError):
                TRANSPORT._read_frame(connection, 256, 1)
        self.assertEqual(connection.recv.call_count, 1)

    def test_invalid_identity_and_boolean_schema_fail_cleanly(self):
        request = dict(schema_version=1, service='opla-evidence', operation='probe',
                       operation_id='op-test', lab_id='lab-ABCD',
                       requested_at='2026-01-01T00:00:00Z', payload={}, evidence={})
        for field, value in [('schema_version', True), ('service', []),
                             ('operation_id', None), ('lab_id', 12)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                CONTRACT.ServiceEnvelope.from_dict({**request, field: value})
