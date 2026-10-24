import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
from qmp import QMP

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

vm = module('vm_ops', 'bin/vm-state.py')
disk = module('vm_disk_ops', 'bin/vm-disk.py')
collect = module('eve_collect_ops', 'xdp/collect.py')
source = module('source_ops', 'bin/source-map.py')
mail = module('mail_ops', 'monitoring/configure-mail.py')
service = module('xdp_ops', 'deploy/xdp-service.py')

class QMPTests(unittest.TestCase):
    def exchange(self, error=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp)/'qmp.sock')
            try:
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            except PermissionError:
                self.skipTest('Environment forbids Unix sockets; protocol tape tests still run')
            listener.bind(path); listener.listen()
            failures=[]
            def server():
                try:
                    conn, _ = listener.accept()
                    with conn, conn.makefile('rwb') as stream:
                        stream.write(b'{"QMP":{"version":{}}}\r\n'); stream.flush()
                        cap=json.loads(stream.readline())
                        stream.write((json.dumps({'return': {}, 'id': cap['id']})+'\r\n').encode());stream.flush()
                        command=json.loads(stream.readline())
                        stream.write(b'{"event":"STOP"}\r\n')
                        answer={'error': {'class':'GenericError','desc':'unsupported'}} if error else {'return': {'running':True}}
                        answer['id']=command['id']
                        raw=(json.dumps(answer)+'\r\n').encode()
                        stream.write(raw[:9]);stream.flush()
                        stream.write(raw[9:]);stream.flush()
                except Exception as e:
                    failures.append(e)
            thread=threading.Thread(target=server);thread.start()
            try:
                with QMP(path, timeout=2) as q:
                    if error:
                        with self.assertRaises(RuntimeError):q.call('query-status')
                    else:self.assertTrue(q.call('query-status')['running'])
            finally:
                thread.join(timeout=3);listener.close()
            self.assertFalse(thread.is_alive());self.assertFalse(failures)

    def tape(self, error=False):
        import io
        class Tape:
            def __init__(self):
                answer = {'id': 2, 'error': {'desc': 'failed'}} if error else {'id': 2, 'return': {'running': True}}
                self.incoming = io.BytesIO(b'{"QMP":{}}\r\n{"id":1,"return":{}}\r\n{"event":"STOP"}\r\n' + json.dumps(answer).encode()+b'\r\n')
                self.outgoing = io.BytesIO()
            def readline(self, limit): return self.incoming.readline(limit)
            def write(self, data): return self.outgoing.write(data)
            def flush(self): pass
            def close(self): pass
        tape = Tape()
        with patch('qmp.socket.socket') as factory:
            factory.return_value.makefile.return_value=tape
            with QMP('/unused', timeout=2) as q:
                if error:
                    with self.assertRaises(RuntimeError):q.call('query-status')
                else:self.assertTrue(q.call('query-status')['running'])
        requests=[json.loads(x) for x in tape.outgoing.getvalue().splitlines()]
        self.assertEqual([x['execute'] for x in requests],['qmp_capabilities','query-status'])
    def test_qmp_protocol_tape_handles_asynchronous_event(self): self.tape()
    def test_qmp_protocol_tape_propagates_error(self): self.tape(True)

    def test_unix_protocol_handles_events_and_partial_response(self): self.exchange()
    def test_qmp_error_does_not_report_success(self): self.exchange(True)
    def test_hmp_tag_rejects_injection(self):
        for tag in ['a; quit', 'x\nquit', '../file', '', 'x'*49]:
            with self.assertRaises(Exception):vm.tag(tag)
        self.assertEqual(vm.tag('before-test_01'), 'before-test_01')
    def test_load_requires_stopped_collector(self):
        import fcntl
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);lab=root/'lab-test'
            folder=root/'monitoring/runtime'/lab.name;folder.mkdir(parents=True)
            with (folder/'collector.lock').open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with patch.object(vm,'ROOT',root):
                    with self.assertRaises(RuntimeError):vm.require_stopped_collector(lab)
    def test_backup_rejects_any_running_vm(self):
        with patch.object(disk,'run',return_value='123'):
            with self.assertRaises(RuntimeError):disk.offline({'LAB_ID':'lab-test'})
    def test_restore_checksum_failure_does_not_touch_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); (p/'victim.qcow2').write_bytes(b'backup')
            (p/'manifest.json').write_text(json.dumps({'images':{'victim':{'file':'victim.qcow2','sha256':'bad'}}}))
            with patch.object(disk,'validate_image') as check:
                with self.assertRaises(RuntimeError):disk.restore(p/'lab',p,'victim')
                check.assert_not_called()

class EVETests(unittest.TestCase):
    def test_alert_drop_not_double_counted_and_cursor_incremental(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);log=p/'eve.json'
            rows=[{'event_type':'alert','alert':{'action':'blocked'}},
                  {'event_type':'drop','drop':{'reason':'rule drop'}},
                  {'event_type':'alert','alert':{'action':'allowed'}},
                  {'event_type':'stats','stats':{'capture':{'kernel_drops':7}}}]
            log.write_text(''.join(json.dumps(x)+'\n' for x in rows)+'invalid\n'+ '{"event_type":')
            first=collect.ids_snapshot(log,p/'state',enabled=1,up=1)
            self.assertEqual(first['ids_alerts'],2);self.assertEqual(first['ids_blocked'],1)
            self.assertEqual(first['ids_kernel_drops'],7);self.assertEqual(first['ids_parse_errors'],1)
            self.assertEqual(collect.ids_snapshot(log,p/'state',enabled=1,up=1),first)
            with log.open('a') as f:f.write('"alert","alert":{"action":"allowed"}}\n')
            second=collect.ids_snapshot(log,p/'state',enabled=1,up=1)
            self.assertEqual(second['ids_alerts'],3)
    def test_rotation_keeps_accumulated_alert_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);log=p/'eve'
            row=json.dumps({'event_type':'alert','alert':{'action':'allowed'}})+'\n'
            log.write_text(row);collect.ids_snapshot(log,p/'state',enabled=1,up=1)
            log.rename(p/'old');log.write_text(row)
            self.assertEqual(collect.ids_snapshot(log,p/'state',enabled=1,up=1)['ids_alerts'],2)
    def test_missing_eve_does_not_claim_running_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            data=collect.ids_snapshot(p/'missing',p/'state',enabled=1,up=0)
            self.assertEqual(data['ids_up'],0);self.assertEqual(data['ids_enabled'],1)
    def test_network_byte_order_source_ip(self):
        row={'key':['0x64','0x40','0x00','0x02'],'formatted':{'value':{'count':101,'start_ns':100}}}
        result=source.decode(row,1000000100)
        self.assertEqual(result['source_ip'],'100.64.0.2')
        self.assertEqual(result['window_count'],101)
        self.assertEqual(result['window_age_seconds'],1)
    def test_different_xdp_program_is_not_detached(self):
        with patch.object(sys,'argv',['xdp-service.py','detach','--interface','eth0']), \
             patch.object(service,'current',return_value={'attached':'drv','prog':{'id':123}}), \
             patch.object(service,'owned_id',return_value=456),patch.object(service,'run') as run:
            with self.assertRaises(RuntimeError):service.main()
            run.assert_not_called()

class MailTests(unittest.TestCase):
    def config(self):
        return {'server':'smtp.example.org','port':587,'sender':'a@example.org',
                'recipient':'b@example.org','username':'a','password':'secret',
                'zabbix_user':'Admin','security':'starttls'}
    def test_plaintext_smtp_is_rejected(self):
        c=self.config();c['security']='none'
        with self.assertRaises(ValueError):mail.validate(c)
    def test_header_injection_is_rejected(self):
        c=self.config();c['recipient']='a@example.org\nBcc:x@example.org'
        with self.assertRaises(ValueError):mail.validate(c)
    def test_configure_preserves_other_media_and_limits_action(self):
        class Fake:
            def __init__(self):self.calls=[]
            def call(self,method,params):
                self.calls.append((method,params))
                return {'user.get':[{'userid':'1','medias':[{'mediatypeid':'other','sendto':['keep@example.org'],'active':0,'severity':63,'period':'1-7,00:00-24:00'}]}],
                        'hostgroup.get':[{'groupid':'10'}],'mediatype.get':[{'mediatypeid':'20'}],
                        'action.get':[{'actionid':'30'}]}.get(method,{})
        fake=Fake();mail.configure(fake,self.config())
        calls=dict(fake.calls)
        self.assertEqual(calls['mediatype.update']['smtp_verify_peer'],1)
        self.assertEqual(calls['user.update']['medias'][0]['sendto'],['keep@example.org'])
        self.assertEqual(calls['action.update']['filter']['conditions'][0]['value'],'10')
        self.assertEqual(len(calls['action.update']['recovery_operations']),1)

class SuricataTransactionTests(unittest.TestCase):
    def test_invalid_candidate_does_not_replace_active_rules(self):
        manager=module('suricata_transaction','security/suricata/manage.py')
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);config=root/'etc';config.mkdir();log=root/'log'
            old=config/'opla.rules';old.write_text('old rules')
            with patch.object(manager,'ROOT',config),patch.object(manager,'LOG',log), \
                 patch.object(manager,'UNIT',root/'unit'), \
                 patch.object(manager,'config',return_value={}), \
                 patch.object(manager,'run',side_effect=subprocess.CalledProcessError(1,'suricata -T')):
                with self.assertRaises(subprocess.CalledProcessError):manager.apply('ids','100.64.0.0/29')
            self.assertEqual(old.read_text(),'old rules')
