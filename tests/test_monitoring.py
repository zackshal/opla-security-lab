import importlib.util
import contextlib
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'xdp'))
sys.path.insert(0,str(ROOT/'monitoring'))
import collect
import bridge
class MonitoringTests(unittest.TestCase):
    def test_large_byte_counter(self):
        n=2**42+1027
        self.assertEqual(collect.number([hex(b) for b in n.to_bytes(8,sys.byteorder)]),n)
    def test_per_cpu_aggregation(self):
        replies=[ [{'xdp':{'attached':'generic','prog':{'id':4}}}],
                  {'id':4},
                  [{'key':['0x02','0x00','0x00','0x00'],'values':[
                    {'cpu':0,'value':300},{'cpu':1,'value':['0x01','0x01','0x00','0x00','0x00','0x00','0x00','0x00']}]}]]
        with patch.object(collect,'run',side_effect=replies):
            self.assertEqual(collect.snapshot()['drop'],557)
    def test_detached_is_not_native(self):
        with patch.object(collect,'run',return_value=[{}]):
            self.assertEqual(collect.snapshot()['loaded'],0)
    def test_wrong_program_rejected(self):
        with patch.object(collect,'run',side_effect=[[{'xdp':{'attached':'drv','prog':{'id':9}}}],{'id':4}]):
            with self.assertRaises(ValueError): collect.snapshot()
    def test_iproute_attached_list(self):
        link={'mode':1,'attached':[{'mode':1,'prog':{'id':57}}]}
        replies=[[{'xdp':link}], {'id':57}, []]
        with patch.object(collect,'run',side_effect=replies):
            data=collect.snapshot()
            self.assertEqual(data['mode'],'native')
            self.assertEqual(data['loaded'],1)
    def test_generic_mode_string(self):
        self.assertEqual(collect.attachment_mode({'attached':'generic','prog':{'id':4}},4),'generic')
    def test_nested_wrong_program_rejected(self):
        with self.assertRaises(ValueError):
            collect.attachment_mode({'attached':[{'mode':1,'prog':{'id':3}}]},4)

    def test_collector_uses_management_ip_and_pinned_host_key(self):
        data = {key: 0 for key in bridge.METRICS}
        data.update(mode='native', scan_details='No event')
        result = SimpleNamespace(returncode=0, stdout=json.dumps(data), stderr='')
        with patch.object(bridge, 'ssh_ip', return_value='100.64.0.11') as map_ip, \
                patch.object(bridge, 'run_bounded', return_value=result) as dispatch:
            self.assertEqual(bridge.collect('100.64.0.3', '/lab/lab-ABCDEFGH'), data)
        map_ip.assert_called_once_with('/lab/lab-ABCDEFGH', '100.64.0.3')
        command = dispatch.call_args.args[0]
        self.assertIn('student@100.64.0.11', command)
        self.assertNotIn('student@100.64.0.3', command)
        self.assertIn('StrictHostKeyChecking=yes', command)
        self.assertIn('UserKnownHostsFile=/lab/lab-ABCDEFGH/known_hosts', command)
        self.assertEqual(dispatch.call_args.kwargs['timeout'], 10)
        self.assertEqual(dispatch.call_args.kwargs['max_output_bytes'], 128 * 1024)

    def test_collector_rejects_limited_guest_output(self):
        result = SimpleNamespace(returncode=0, stdout='{}', stderr='', output_limited=True)
        with patch.object(bridge, 'ssh_ip', return_value='100.64.0.11'), \
                patch.object(bridge, 'run_bounded', return_value=result):
            with self.assertRaisesRegex(ValueError, '128 KiB'):
                bridge.collect('100.64.0.3', '/lab/lab-ABCDEFGH')

    def test_collector_timeout_is_not_converted_to_empty_snapshot(self):
        with patch.object(bridge, 'ssh_ip', return_value='100.64.0.11'), \
                patch.object(bridge, 'run_bounded', side_effect=subprocess.TimeoutExpired('ssh', 10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                bridge.collect('100.64.0.3', '/lab/lab-ABCDEFGH')

    def test_collector_malformed_snapshot_is_rejected(self):
        for payload, error in (('not-json', json.JSONDecodeError), ('[]', ValueError), ('null', ValueError)):
            with self.subTest(payload=payload):
                result = SimpleNamespace(returncode=0, stdout=payload, stderr='')
                with patch.object(bridge, 'ssh_ip', return_value='100.64.0.11'), \
                        patch.object(bridge, 'run_bounded', return_value=result):
                    with self.assertRaises(error):
                        bridge.collect('100.64.0.3', '/lab/lab-ABCDEFGH')

    def test_collector_rejects_malformed_snapshot_fields(self):
        valid={key:0 for key in bridge.METRICS}
        valid.update(mode='native',scan_details='No event')
        cases=[]
        missing=dict(valid);missing.pop(bridge.METRICS[0]);cases.append(missing)
        negative=dict(valid);negative[bridge.METRICS[0]]=-1;cases.append(negative)
        boolean=dict(valid);boolean[bridge.METRICS[0]]=True;cases.append(boolean)
        wrong_mode=dict(valid);wrong_mode['mode']=1;cases.append(wrong_mode)
        wrong_scan=dict(valid);wrong_scan['scan_details']=None;cases.append(wrong_scan)
        for data in cases:
            with self.subTest(data=data):
                result=SimpleNamespace(returncode=0,stdout=json.dumps(data),stderr='')
                with patch.object(bridge,'ssh_ip',return_value='100.64.0.11'), \
                        patch.object(bridge,'run_bounded',return_value=result):
                    with self.assertRaises(ValueError):
                        bridge.collect('100.64.0.3','/lab/lab-ABCDEFGH')

    def test_collector_once_failure_persists_error_and_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            runtime = repo / '.local/state/opla/monitoring/runtime/lab-ABCDEFGH'
            with patch.object(bridge.Path, 'home', return_value=repo), \
                    patch.object(bridge, 'load', return_value={
                        'LAB_ID': 'lab-ABCDEFGH', 'VICTIM_IP': '100.64.0.3'}), \
                    patch.object(bridge, 'collect', side_effect=subprocess.TimeoutExpired('ssh', 10)), \
                    patch.object(sys, 'argv', ['bridge.py', '--lab', '/lab/lab-ABCDEFGH', '--once']), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bridge.main(), 1)
            events = [json.loads(row) for row in (runtime / 'events.jsonl').read_text().splitlines()]
            self.assertEqual(events[-1]['event'], 'collection_error')
            self.assertIn('timed out', events[-1]['error'])

    def test_collector_once_success_sends_one_snapshot_without_sleep(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo=Path(temporary)
            runtime=repo/'.local/state/opla/monitoring/runtime/lab-ABCDEFGH'
            data={key:0 for key in bridge.METRICS}
            data.update(mode='native',scan_details='No event')
            with patch.object(bridge.Path,'home',return_value=repo), \
                    patch.object(bridge,'load',return_value={
                        'LAB_ID':'lab-ABCDEFGH','VICTIM_IP':'100.64.0.3'}), \
                    patch.object(bridge,'collect',return_value=data), \
                    patch.object(bridge,'send') as send, \
                    patch.object(bridge.time,'sleep',side_effect=AssertionError('once mode must not sleep')), \
                    patch.object(sys,'argv',['bridge.py','--lab','/lab/lab-ABCDEFGH','--once']):
                self.assertEqual(bridge.main(),0)
            self.assertEqual(send.call_count,1)
            records=send.call_args.args[0]
            self.assertTrue(any(item['key']=='xdp.events' for item in records))
            self.assertEqual(json.loads((runtime/'pending-events.json').read_text()),[])

    def test_collector_lock_contention_stops_before_guest_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            with patch.object(bridge.Path, 'home', return_value=repo), \
                    patch.object(bridge, 'load', return_value={
                        'LAB_ID': 'lab-ABCDEFGH', 'VICTIM_IP': '100.64.0.3'}), \
                    patch.object(bridge.fcntl, 'flock', side_effect=BlockingIOError), \
                    patch.object(bridge, 'collect') as collect, \
                    patch.object(sys, 'argv', ['bridge.py', '--lab', '/lab/lab-ABCDEFGH', '--once']):
                self.assertEqual(bridge.main(), 1)
            collect.assert_not_called()

    def test_collector_rejects_nonfinite_interval(self):
        for interval in ('nan', 'inf', '-inf'):
            with self.subTest(interval=interval), \
                    patch.object(sys, 'argv', ['bridge.py', '--lab', '/lab/lab-ABCDEFGH',
                                               f'--interval={interval}']), \
                    patch.object(bridge, 'load') as load:
                with self.assertRaises(SystemExit) as raised:
                    bridge.main()
                self.assertEqual(raised.exception.code, 2)
                load.assert_not_called()

    def test_failed_zabbix_send_retries_pending_event_on_next_sample(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            runtime = repo / '.local/state/opla/monitoring/runtime/lab-ABCDEFGH'
            data = {key: 0 for key in bridge.METRICS}
            data.update(mode='native', scan_details='No event')
            successful_records = []
            attempts = 0
            sleep_calls = 0
            def send(records):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError('temporary Zabbix failure')
                successful_records.extend(records)
                return {'response': 'success'}
            def stop_after_retry(_delay):
                nonlocal sleep_calls
                sleep_calls += 1
                if sleep_calls == 2:
                    raise KeyboardInterrupt
            with patch.object(bridge.Path, 'home', return_value=repo), \
                    patch.object(bridge, 'load', return_value={
                        'LAB_ID': 'lab-ABCDEFGH', 'VICTIM_IP': '100.64.0.3'}), \
                    patch.object(bridge, 'collect', return_value=data), \
                    patch.object(bridge, 'send', side_effect=send), \
                    patch.object(bridge.time, 'sleep', side_effect=stop_after_retry), \
                    patch.object(sys, 'argv', ['bridge.py', '--lab', '/lab/lab-ABCDEFGH']):
                with self.assertRaises(KeyboardInterrupt):
                    bridge.main()
            event_records = [item for item in successful_records if item['key'] == 'xdp.events']
            self.assertEqual(len(event_records), 1)

    def test_pending_event_outbox_survives_collector_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            runtime = repo / '.local/state/opla/monitoring/runtime/lab-ABCDEFGH'
            data = {key: 0 for key in bridge.METRICS}
            data.update(mode='native', scan_details='No event')
            with patch.object(bridge.Path, 'home', return_value=repo), \
                    patch.object(bridge, 'load', return_value={
                        'LAB_ID': 'lab-ABCDEFGH', 'VICTIM_IP': '100.64.0.3'}), \
                    patch.object(bridge, 'collect', return_value=data), \
                    patch.object(bridge, 'send', side_effect=OSError('Zabbix unavailable')), \
                    patch.object(sys, 'argv', ['bridge.py', '--lab', '/lab/lab-ABCDEFGH', '--once']), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bridge.main(), 1)
            outbox = runtime / 'pending-events.json'
            before_restart = json.loads(outbox.read_text())
            self.assertEqual(len(before_restart), 1)

            delivered = []
            with patch.object(bridge.Path, 'home', return_value=repo), \
                    patch.object(bridge, 'load', return_value={
                        'LAB_ID': 'lab-ABCDEFGH', 'VICTIM_IP': '100.64.0.3'}), \
                    patch.object(bridge, 'collect', return_value=data), \
                    patch.object(bridge, 'send', side_effect=lambda records: delivered.extend(records)), \
                    patch.object(sys, 'argv', ['bridge.py', '--lab', '/lab/lab-ABCDEFGH', '--once']):
                self.assertEqual(bridge.main(), 0)
            self.assertIn(before_restart[0], delivered)
            self.assertEqual(len([item for item in delivered if item['key']=='xdp.events']),1)
            self.assertEqual(json.loads(outbox.read_text()), [])

    def test_pending_event_limit_refuses_to_discard_existing_backlog(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'pending.json'
            original = [{'host': 'h', 'key': 'xdp.events', 'value': 'old', 'clock': 1}]
            bridge.save_pending(path, original)
            overflow = original * (bridge.MAX_PENDING_EVENTS + 1)
            with self.assertRaisesRegex(ValueError, 'refusing to drop'):
                bridge.save_pending(path, overflow)
            self.assertEqual(bridge.load_pending(path), original)

    def test_pending_byte_limit_and_atomic_replace_failure_preserve_old_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'pending.json'
            original=[{'host':'h','key':'xdp.events','value':'old','clock':1}]
            bridge.save_pending(path,original)
            too_large=[{'host':'h','key':'xdp.events',
                        'value':'x'*bridge.MAX_PENDING_BYTES,'clock':2}]
            with self.assertRaisesRegex(ValueError,'size limit'):
                bridge.save_pending(path,too_large)
            self.assertEqual(bridge.load_pending(path),original)
            with patch.object(bridge.os,'replace',side_effect=OSError('rename failed')):
                with self.assertRaisesRegex(OSError,'rename failed'):
                    bridge.save_pending(path,[{'host':'h','key':'xdp.events','value':'new','clock':3}])
            self.assertEqual(bridge.load_pending(path),original)
            self.assertEqual(list(Path(temporary).glob('.pending-*')),[])

    def test_pending_event_outbox_rejects_symlink_and_malformed_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'target.json'
            target.write_text('[]')
            link = root / 'linked.json'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                bridge.load_pending(link)
            malformed = root / 'malformed.json'
            malformed.write_text('[{"unexpected":true}]')
            with self.assertRaisesRegex(ValueError, 'invalid records'):
                bridge.load_pending(malformed)

    def test_event_log_rotation_keeps_previous_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'events.jsonl'
            original = b'x' * (5 * 1024 * 1024 + 1)
            path.write_bytes(original)
            bridge.append_log(path, {'event': 'after-rotation'})
            self.assertEqual(path.with_suffix('.jsonl.1').read_bytes(), original)
            self.assertEqual(json.loads(path.read_text().strip()), {'event': 'after-rotation'})

    def test_event_log_rotation_retains_one_previous_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'events.jsonl'
            path.write_bytes(b'a'*(5*1024*1024+1))
            bridge.append_log(path,{'event':'second-generation'})
            first_backup=path.with_suffix('.jsonl.1').read_bytes()
            path.write_bytes(b'b'*(5*1024*1024+1))
            bridge.append_log(path,{'event':'third-generation'})
            self.assertEqual(path.with_suffix('.jsonl.1').read_bytes(),b'b'*(5*1024*1024+1))
            self.assertNotEqual(path.with_suffix('.jsonl.1').read_bytes(),first_backup)

    def test_event_log_rejects_symlink_without_modifying_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'valuable.jsonl'
            target.write_text('preserve')
            link = root / 'events.jsonl'
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                bridge.append_log(link, {'event': 'blocked'})
            self.assertEqual(target.read_text(), 'preserve')

    def test_runtime_directory_rejects_symlinked_lab_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo=Path(temporary)
            (repo/'.local/state/opla/monitoring/runtime').mkdir(parents=True)
            target=repo/'outside'
            target.mkdir()
            (repo/'.local/state/opla/monitoring/runtime/lab-ABCDEFGH').symlink_to(target,target_is_directory=True)
            with patch.object(bridge.Path,'home',return_value=repo):
                with self.assertRaisesRegex(ValueError,'unsafe monitoring runtime directory'):
                    bridge.prepare_runtime('lab-ABCDEFGH')

    def test_zabbix_sender_rejects_non_object_ack(self):
        payload = b'[]'
        frame = b'ZBXD\x01' + struct.pack('<Q', len(payload)) + payload
        class FakeSocket:
            def __init__(self):
                self.data = frame
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def sendall(self, _payload):
                pass
            def recv(self, size):
                chunk, self.data = self.data[:size], self.data[size:]
                return chunk
        with patch.object(bridge.socket, 'create_connection', return_value=FakeSocket()):
            with self.assertRaisesRegex(ValueError, 'JSON-объект'):
                bridge.send([{'host': 'test', 'key': 'xdp.loaded', 'value': '1'}])

    def test_zabbix_sender_rejects_non_string_ack_info(self):
        payload = json.dumps({'response':'success','info':1}).encode()
        frame = b'ZBXD\x01' + struct.pack('<Q', len(payload)) + payload
        class FakeSocket:
            def __init__(self): self.data = frame
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def sendall(self, _payload): pass
            def recv(self, size):
                chunk, self.data = self.data[:size], self.data[size:]
                return chunk
        with patch.object(bridge.socket, 'create_connection', return_value=FakeSocket()):
            with self.assertRaisesRegex(ValueError, 'info должно быть строкой'):
                bridge.send([{'host':'test','key':'xdp.loaded','value':'1'}])

    def exchange(self,reply):
        listener = None
        try:
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
        except PermissionError:
            if listener is not None:
                listener.close()
            self.skipTest('Environment forbids local TCP sockets')
        got=[]
        def server():
            with listener:
                conn,_=listener.accept()
                with conn:
                    h=bridge.recv_exact(conn,13)
                    got.append(json.loads(bridge.recv_exact(conn,struct.unpack('<Q',h[5:])[0])))
                    body=json.dumps(reply).encode()
                    frame=b'ZBXD\x01'+struct.pack('<Q',len(body))+body
                    # TCP has no message boundaries: deliberately fragment the response.
                    for b in frame: conn.sendall(bytes([b]))
        thread=threading.Thread(target=server);thread.start()
        try:
            result=bridge.send([{'host':'test','key':'xdp.loaded','value':'1'}],port=listener.getsockname()[1])
            self.assertEqual(got[0]['request'],'sender data')
            return result
        finally:thread.join(timeout=5)
    def test_sender_framing(self):
        self.exchange({'response':'success','info':'processed: 1; failed: 0; total: 1; seconds spent: 0.1'})
    def test_sender_partial_failure(self):
        with self.assertRaises(ValueError):
            self.exchange({'response':'success','info':'processed: 0; failed: 1; total: 1; seconds spent: 0.1'})
