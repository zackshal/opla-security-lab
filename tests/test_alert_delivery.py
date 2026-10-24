import importlib.util
from email.policy import SMTP
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('alert_delivery', Path(__file__).resolve().parents[1] / 'monitoring/alert_delivery.py')
mail = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mail)


def config():
    return dict(api_url='http://127.0.0.1:8080/api_jsonrpc.php', api_token='a' * 64,
                host='opla-lab-test', sender='example@gmail.com', smtp_password='b' * 16,
                recipients=['example@gmail.com', 'example@proton.me'])


def event(eid='101', recovered='0', severity='2'):
    return dict(eventid=eid, clock='1792847103', severity=severity, name='XDP is detached',
                r_eventid=recovered, hosts=[dict(host='opla-lab-test', name='Lab')])


class FakeAPI:
    def __init__(self, new, active=None, recovered=None):
        self.new = new
        self.active = active or []
        self.recovered = recovered or {}
        self.requests = []

    def host_id(self):
        return '42'

    def call(self, method, params):
        self.requests.append((method, params))
        lower = int(params.get('eventid_from', '0'))
        return [{'eventid': e['eventid']} for e in self.active if int(e['eventid']) >= lower][:params.get('limit', 200)]

    def events(self, params):
        self.requests.append(('event.get', params))
        if 'eventids' in params:
            all_rows = {e['eventid']: e for e in self.new + self.active}
            all_rows.update(self.recovered)
            return [all_rows[eid] for eid in params['eventids'] if eid in all_rows]
        return [e for e in self.new if int(e['eventid']) >= int(params['eventid_from'])][:params.get('limit', 200)]


class AlertsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.c = config()
        self.q = mail.Queue(Path(self.directory.name), self.c)

    def tearDown(self):
        self.q.db.close()
        self.directory.cleanup()

    def test_problem_and_recovery_to_each_recipient_once(self):
        api = FakeAPI([event(recovered='102')], recovered={'102': dict(eventid='102', clock='1792847203')})
        mail.poll(api, self.q, self.c)
        mail.poll(api, self.q, self.c)
        self.assertEqual(self.q.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 4)
        self.assertEqual([j['kind'] for j in self.q.due(1e12)], ['PROBLEM', 'PROBLEM'])
        for job in self.q.due(1e12):
            self.q.complete(job, None, 100)
        self.assertEqual([j['kind'] for j in self.q.due(1e12)], ['RECOVERY', 'RECOVERY'])

    def test_existing_problem_is_included(self):
        mail.poll(FakeAPI([], active=[event()]), self.q, self.c)
        self.assertEqual(self.q.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 2)

    def test_event_pagination_does_not_skip_equal_timestamps(self):
        rows = [event(eid=str(x)) for x in range(1000, 1205)]
        mail.poll(FakeAPI(rows), self.q, self.c)
        self.assertEqual(self.q.db.execute('SELECT count(*) FROM events').fetchone()[0], 205)
        self.assertEqual(self.q.meta('cursor'), '1204')

    def test_api_outage_has_one_problem_and_one_recovery_per_recipient(self):
        for now in range(5):
            mail.record_poll_result(self.q, self.c, 'ConnectionError', now)
        self.assertEqual(self.q.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 2)
        mail.record_poll_result(self.q, self.c, None, 6)
        mail.record_poll_result(self.q, self.c, None, 7)
        self.assertEqual(self.q.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 4)

    def test_warning_and_above_host_scope(self):
        api = FakeAPI([])
        mail.poll(api, self.q, self.c)
        query = api.requests[0][1]
        self.assertEqual(query['severities'], [2, 3, 4, 5])
        self.assertEqual(query['hostids'], ['42'])
        self.assertEqual(query['value'], 1)

    def test_queue_survives_restart(self):
        with self.q.db:
            self.q.remember(event(), self.c['recipients'])
        self.q.db.close()
        self.q = mail.Queue(Path(self.directory.name), self.c)
        self.assertEqual(len(self.q.due(100)), 2)

    def test_retry_is_per_recipient_and_does_not_resend_success(self):
        with self.q.db:
            self.q.remember(event(), self.c['recipients'])
        jobs = self.q.due(100)
        self.q.complete(jobs[0], 'curl exit 67', 100)
        self.q.complete(jobs[1], None, 100)
        self.assertEqual(len(self.q.due(129)), 0)
        retry = self.q.due(130)
        self.assertEqual(len(retry), 1)
        self.assertEqual(retry[0]['recipient'], jobs[0]['recipient'])

    def test_recipient_order_keeps_recovery_after_problem(self):
        with self.q.db:
            self.q.add(event(), 'PROBLEM', self.c['recipients'])
            self.q.add(event(), 'RECOVERY', self.c['recipients'])
        jobs = self.q.due(0)
        self.q.complete(jobs[0], 'curl exit 7', 0)
        self.q.complete(jobs[1], None, 0)
        due = self.q.due(1)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0]['kind'], 'RECOVERY')
        self.assertEqual(due[0]['recipient'], jobs[1]['recipient'])

    def test_smtp_uses_tor_tls_and_keeps_password_out_of_argv(self):
        job = dict(eventid='101', kind='PROBLEM', recipient='example@proton.me', payload=json.dumps(event()))
        def runner(command, **kwargs):
            self.assertIn('--socks5-hostname', command)
            self.assertIn('--ssl-reqd', command)
            self.assertNotIn('--insecure', command)
            self.assertNotIn(self.c['smtp_password'], ' '.join(command))
            self.assertIn(self.c['smtp_password'], kwargs['input'])
            self.assertEqual(command[command.index('--noproxy') + 1], '')
            path = Path(command[-1])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            return subprocess.CompletedProcess(command, 0)
        self.assertIsNone(mail.send(self.c, job, runner))

    def test_failed_smtp_never_falls_back_to_direct_or_logs_secret(self):
        calls = []
        job = dict(eventid='101', kind='PROBLEM', recipient='example@proton.me', payload=json.dumps(event()))
        def runner(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 67, stderr=self.c['smtp_password'])
        error = mail.send(self.c, job, runner)
        self.assertEqual(error, 'curl exit 67')
        self.assertEqual(len(calls), 1)

    def test_scope_cannot_silently_change(self):
        with self.assertRaises(ValueError):
            mail.Queue(Path(self.directory.name), dict(self.c, host='another-host'))

    def test_rejects_header_injection_and_remote_api(self):
        with self.assertRaises(ValueError):
            mail.validate(dict(self.c, sender='example@gmail.com\r\nBcc: other@example.org'))
        with self.assertRaises(ValueError):
            mail.validate(dict(self.c, api_url='http://remote.example/api_jsonrpc.php'))

    def test_secret_file_permissions(self):
        filename = Path(self.directory.name) / 'config.json'
        filename.write_text(json.dumps(self.c))
        filename.chmod(0o644)
        with self.assertRaises(ValueError):
            mail.load_config(filename)
        filename.chmod(0o600)
        self.assertEqual(mail.load_config(filename), self.c)

    def test_api_failure_does_not_advance_cursor(self):
        class Broken(FakeAPI):
            def events(self, params):
                raise ConnectionError('offline')
        with self.assertRaises(ConnectionError):
            mail.poll(Broken([]), self.q, self.c)
        self.assertIsNone(self.q.meta('cursor'))

    def test_stable_message_id_and_safe_subject(self):
        e = dict(event(), name='Bad\r\nBcc: injection')
        job = dict(eventid='101', kind='PROBLEM', recipient='example@proton.me', payload=json.dumps(e))
        from email.parser import BytesParser
        first = BytesParser(policy=SMTP).parsebytes(mail.message_bytes(self.c, job))
        second = BytesParser(policy=SMTP).parsebytes(mail.message_bytes(self.c, job))
        self.assertEqual(first['Message-ID'], second['Message-ID'])
        self.assertIsNone(first['Bcc'])


if __name__ == '__main__':
    unittest.main()
