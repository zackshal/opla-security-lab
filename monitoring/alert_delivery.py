#!/usr/bin/env python3
"""Read Zabbix trigger events and queue verified SMTP deliveries through Tor."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
import uuid

CONFIG = Path.home() / '.config/opla/alerts.json'
STATE = Path.home() / '.local/state/opla-alerts'
LEVELS = ['Not classified', 'Information', 'Warning', 'Average', 'High', 'Disaster']
ADDRESS = re.compile(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


def log(kind, **fields):
    print(json.dumps(dict(time=datetime.now(timezone.utc).isoformat(), kind=kind, **fields)), flush=True)


def private_directory(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid():
        raise ValueError('State/config directory must belong to the current user')
    os.chmod(directory, 0o700)


def validate(config):
    if config.get('api_url') != 'http://127.0.0.1:8080/api_jsonrpc.php':
        raise ValueError('Only the local OPLA API endpoint is supported')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', config.get('host', '')):
        raise ValueError('Invalid technical host name')
    if not re.fullmatch(r'[A-Fa-f0-9]{64}', config.get('api_token', '')):
        raise ValueError('Expected a Zabbix API token of 64 hexadecimal characters')
    if not ADDRESS.fullmatch(config.get('sender', '')) or not config['sender'].lower().endswith('@gmail.com'):
        raise ValueError('Use the authenticated Gmail address as sender')
    recipients = config.get('recipients', [])
    if len(recipients) != 2 or len(set(recipients)) != 2 or any(not ADDRESS.fullmatch(x) for x in recipients):
        raise ValueError('Two distinct recipient addresses are required')
    if not re.fullmatch(r'[A-Za-z0-9]{16}', config.get('smtp_password', '')):
        raise ValueError('Expected a 16-character Gmail app password')
    return config


def load_config(filename):
    if filename.is_symlink():
        raise ValueError('Configuration must not be a symlink')
    st = filename.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError('Configuration must be owned by the current user and have mode 0600')
    return validate(json.loads(filename.read_text()))


class API:
    def __init__(self, config):
        self.config = config
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, params):
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
        if method != 'apiinfo.version':
            payload['auth'] = self.config['api_token']
        request = urllib.request.Request(self.config['api_url'], json.dumps(payload).encode(),
                                         {'Content-Type': 'application/json-rpc'})
        with self.opener.open(request, timeout=15) as response:
            result = json.loads(response.read(16 * 1024 * 1024))
        if 'error' in result:
            raise RuntimeError('Zabbix API rejected ' + method + '; check token permissions and server logs')
        return result['result']

    def host_id(self):
        hosts = self.call('host.get', {'filter': {'host': [self.config['host']]}, 'output': ['hostid', 'status']})
        if len(hosts) != 1 or hosts[0]['status'] != '0':
            raise ValueError('Configured host is missing, disabled, or not visible to the API user')
        return hosts[0]['hostid']

    def events(self, params):
        return self.call('event.get', dict(output='extend', selectHosts=['host', 'name'], **params))


class Queue:
    def __init__(self, directory, config):
        private_directory(directory)
        self.db = sqlite3.connect(directory / 'queue.sqlite3')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (eventid TEXT PRIMARY KEY, payload TEXT NOT NULL, recovered INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY, eventid TEXT NOT NULL, kind TEXT NOT NULL,
                recipient TEXT NOT NULL, payload TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                next_try REAL NOT NULL DEFAULT 0, sent REAL, last_error TEXT,
                UNIQUE(eventid,kind,recipient));
        ''')
        signature = hashlib.sha256((config['api_url'] + '\n' + config['host']).encode()).hexdigest()
        if self.meta('scope') not in (None, signature):
            self.db.close()
            raise ValueError('This state directory belongs to another host/API; choose another --state directory')
        with self.db:
            self.set_meta('scope', signature)
            if self.meta('start_time') is None:
                self.set_meta('start_time', str(int(time.time())))

    def meta(self, key):
        row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return row['value'] if row else None

    def set_meta(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, str(value)))

    def add(self, event, kind, recipients):
        payload = json.dumps(event, ensure_ascii=False)
        for recipient in recipients:
            self.db.execute('INSERT OR IGNORE INTO jobs(eventid,kind,recipient,payload) VALUES (?,?,?,?)',
                            (event['eventid'], kind, recipient, payload))

    def remember(self, event, recipients):
        if self.db.execute('INSERT OR IGNORE INTO events(eventid,payload) VALUES (?,?)',
                           (event['eventid'], json.dumps(event))).rowcount:
            self.add(event, 'PROBLEM', recipients)

    def due(self, now):
        return self.db.execute('''SELECT j.* FROM jobs j WHERE sent IS NULL AND next_try<=?
            AND NOT EXISTS (SELECT 1 FROM jobs older WHERE older.recipient=j.recipient
                            AND older.sent IS NULL AND older.id<j.id)
            ORDER BY j.id LIMIT 2''', (now,)).fetchall()

    def complete(self, job, error, now):
        with self.db:
            if error is None:
                self.db.execute('UPDATE jobs SET sent=?,last_error=NULL WHERE id=?', (now, job['id']))
            else:
                delay = min(3600, 30 * 2 ** min(job['attempts'], 7))
                self.db.execute('UPDATE jobs SET attempts=attempts+1,next_try=?,last_error=? WHERE id=?',
                                (now + delay, error, job['id']))
        log('smtp_accepted' if error is None else 'retry_scheduled', eventid=job['eventid'],
            notification=job['kind'], job=job['id'], error=error)


def poll(api, queue, config):
    hid = api.host_id()
    base = dict(source=0, object=0, hostids=[hid], severities=[2, 3, 4, 5],
                sortfield=['eventid'], sortorder='ASC', limit=200)
    # Resume discovery from the durable cursor; short-lived resolved events remain visible.
    for _ in range(10):
        rows = api.events(dict(base, value=1, time_from=int(queue.meta('start_time')),
                               eventid_from=str(int(queue.meta('cursor') or '0') + 1)))
        with queue.db:
            for event in rows:
                queue.remember(event, config['recipients'])
            if rows:
                queue.set_meta('cursor', rows[-1]['eventid'])
        if len(rows) < 200:
            break
    # Also include already active problems and manual severity increases.
    lower = 0
    for _ in range(10):
        rows = api.call('problem.get', dict(base, recent=False, output=['eventid'], eventid_from=str(lower + 1)))
        if rows:
            details = api.events({'eventids': [r['eventid'] for r in rows]})
            with queue.db:
                for event in details:
                    queue.remember(event, config['recipients'])
            lower = int(rows[-1]['eventid'])
        if len(rows) < 200:
            break
    open_ids = [r['eventid'] for r in queue.db.execute('SELECT eventid FROM events WHERE recovered=0')]
    for offset in range(0, len(open_ids), 100):
        rows = api.events({'eventids': open_ids[offset:offset + 100]})
        resolved = [r for r in rows if str(r.get('r_eventid', '0')) != '0']
        if not resolved:
            continue
        recoveries = {r['eventid']: r for r in api.events({'eventids': [r['r_eventid'] for r in resolved]})}
        with queue.db:
            for event in resolved:
                recovery = recoveries.get(event['r_eventid'])
                if recovery is None:
                    continue
                event = dict(event, recovery_clock=recovery['clock'])
                queue.add(event, 'RECOVERY', config['recipients'])
                queue.db.execute('UPDATE events SET recovered=1 WHERE eventid=?', (event['eventid'],))
    with queue.db:
        queue.set_meta('last_poll_ok', int(time.time()))
        queue.set_meta('last_poll_error', '')


def message_bytes(config, job):
    event = json.loads(job['payload'])
    severity = max(0, min(5, int(event.get('severity', 2))))
    title = re.sub(r'[\r\n\x00-\x1f\x7f]+', ' ', event.get('name', 'OPLA notification'))[:180]
    msg = EmailMessage()
    msg['From'], msg['To'] = config['sender'], job['recipient']
    msg['Date'] = formatdate(localtime=False)
    digest = hashlib.sha256((job['eventid'] + job['kind'] + job['recipient']).encode()).hexdigest()[:40]
    msg['Message-ID'] = '<opla-' + digest + '@opla.local>'
    msg['Subject'] = f"[OPLA][{job['kind']}][{LEVELS[severity]}] {title}"
    clock = int(event.get('recovery_clock', event.get('clock', time.time())))
    when = datetime.fromtimestamp(clock, timezone.utc).isoformat()
    hosts = ', '.join(h.get('name', h.get('host', '')) for h in event.get('hosts', []))
    msg.set_content(f"Состояние: {job['kind']}\nКритичность: {LEVELS[severity]}\n"
                    f"Узел: {hosts or config['host']}\nСобытие: {title}\n"
                    f"ID проблемы: {event['eventid']}\nID восстановления: {event.get('r_eventid', '0')}\n"
                    f"Время UTC: {when}\nОперационные данные: {event.get('opdata', '')}\n"
                    f"Zabbix: http://127.0.0.1:8080/zabbix.php?action=problem.view\n\n"
                    "Уведомление сформировано по событию Zabbix. Полные журналы остаются в стенде.\n")
    return msg.as_bytes(policy=SMTP)


def record_poll_result(queue, config, error, now):
    with queue.db:
        if error is not None:
            failures = int(queue.meta('poll_failures') or '0') + 1
            queue.set_meta('poll_failures', failures)
            queue.set_meta('last_poll_error', error)
            if failures >= 3 and not queue.meta('api_incident'):
                event = dict(eventid='local-api-' + uuid.uuid4().hex, clock=str(int(now)),
                             severity='4', name='OPLA delivery worker cannot read Zabbix API', opdata=error)
                queue.set_meta('api_incident', json.dumps(event))
                queue.add(event, 'PROBLEM', config['recipients'])
        else:
            queue.set_meta('poll_failures', 0)
            queue.set_meta('last_poll_error', '')
            queue.set_meta('last_poll_ok', int(now))
            incident = queue.meta('api_incident')
            if incident:
                event = dict(json.loads(incident), recovery_clock=str(int(now)))
                queue.add(event, 'RECOVERY', config['recipients'])
                queue.set_meta('api_incident', '')


def send(config, job, runner=subprocess.run):
    with tempfile.NamedTemporaryFile(prefix='opla-alert-', suffix='.eml') as mail:
        mail.write(message_bytes(config, job))
        mail.flush()
        credentials = 'user = ' + json.dumps(config['sender'] + ':' + config['smtp_password']) + '\n'
        command = ['curl', '-q', '--config', '-', '--silent', '--show-error',
                   '--socks5-hostname', '127.0.0.1:9050', '--noproxy', '',
                   '--connect-timeout', '20', '--max-time', '90',
                   '--url', 'smtp://smtp.gmail.com:587/opla.local', '--ssl-reqd',
                   '--mail-from', config['sender'], '--mail-rcpt', job['recipient'],
                   '--upload-file', mail.name]
        try:
            result = runner(command, input=credentials, text=True, capture_output=True, timeout=100)
        except subprocess.TimeoutExpired:
            return 'curl process timeout; SMTP acceptance uncertain'
        except OSError:
            return 'curl could not be started'
    # Never persist SMTP diagnostics that might contain authentication details.
    return None if result.returncode == 0 else 'curl exit ' + str(result.returncode)


def configure(filename, host):
    private_directory(filename.parent)
    if filename.exists() or filename.is_symlink():
        raise ValueError('Configuration already exists; edit it locally or choose another --config')
    if not host:
        host = input('Technical Zabbix host name (opla-lab-...): ').strip()
    gmail = input('Gmail sender and first recipient: ').strip()
    proton = input('Proton recipient: ').strip()
    config = validate(dict(api_url='http://127.0.0.1:8080/api_jsonrpc.php', host=host,
                           api_token=getpass.getpass('Zabbix API token (hidden): ').strip(),
                           sender=gmail, recipients=[gmail, proton],
                           smtp_password=getpass.getpass('Gmail app password (hidden): ').replace(' ', '')))
    api = API(config)
    if not api.call('apiinfo.version', {}).startswith('7.0.'):
        raise ValueError('Zabbix 7.0 is required')
    api.host_id()
    api.call('problem.get', {'hostids': [api.host_id()], 'output': ['eventid'], 'limit': 1})
    api.events({'hostids': [api.host_id()], 'limit': 1})
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(config, stream, indent=2)
        stream.write('\n')
    print('Saved private configuration. SMTP delivery is tested separately with the test command.')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['configure', 'run', 'test', 'status'])
    parser.add_argument('--config', type=Path, default=CONFIG)
    parser.add_argument('--state', type=Path, default=STATE)
    parser.add_argument('--host')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if args.action == 'configure':
        configure(args.config, args.host)
        return
    config = load_config(args.config)
    if args.action == 'status':
        dbfile = args.state.resolve() / 'queue.sqlite3'
        if not dbfile.exists():
            print('Queue has not been initialized')
            return
        db = sqlite3.connect(dbfile.as_uri() + '?mode=ro', uri=True)
        print('Pending/accepted by SMTP:', db.execute('SELECT sum(sent IS NULL),sum(sent IS NOT NULL) FROM jobs').fetchone())
        print('Poll state:', db.execute("SELECT * FROM meta WHERE key LIKE 'last_poll_%'").fetchall())
        for row in db.execute('SELECT id,eventid,kind,attempts,last_error FROM jobs WHERE sent IS NULL ORDER BY id LIMIT 20'):
            print(row)
        return
    private_directory(args.state)
    with (args.state / 'worker.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Delivery worker already running; stop opla-alerts.service first')
        queue = Queue(args.state, config)
        if args.action == 'test':
            event = dict(eventid='test-' + uuid.uuid4().hex, clock=str(int(time.time())),
                         severity='2', name='Контроль очереди Gmail + Proton через Tor')
            with queue.db:
                queue.add(event, 'TEST', config['recipients'])
        api = API(config)
        inflight = {}
        last_poll = 0
        with ThreadPoolExecutor(max_workers=2) as executor:
            while True:
                now = time.time()
                if args.action == 'run' and now - last_poll >= 15:
                    try:
                        poll(api, queue, config)
                        record_poll_result(queue, config, None, time.time())
                    except Exception as error:
                        # Do not log arbitrary exception messages or HTTP response bodies.
                        category = type(error).__name__
                        record_poll_result(queue, config, category, time.time())
                        log('api_poll_failed', error=category)
                    last_poll = now
                for jid, (job, future) in list(inflight.items()):
                    if future.done():
                        try:
                            error = future.result()
                        except Exception:
                            error = 'delivery worker failed'
                        queue.complete(job, error, time.time())
                        del inflight[jid]
                for job in queue.due(time.time()):
                    if len(inflight) < 2 and job['id'] not in inflight:
                        inflight[job['id']] = (job, executor.submit(send, config, dict(job)))
                if args.once or args.action == 'test':
                    for job, future in list(inflight.values()):
                        try:
                            error = future.result()
                        except Exception:
                            error = 'delivery worker failed'
                        queue.complete(job, error, time.time())
                    print('One cycle completed; use status to inspect pending deliveries')
                    return
                time.sleep(1)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error))
