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
import stat
import subprocess
import tempfile
import time
import urllib.request
import uuid

CONFIG = Path.home() / '.config/opla/alerts.json'
STATE = Path.home() / '.local/state/opla-alerts'
XDG_CONFIG = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
SELECTION = Path(os.environ.get('OPLA_LAB_SELECTION', str(XDG_CONFIG / 'opla/selected-lab')))
LAB_ROOT = Path('/var/lib/opla')
LEVELS = ['Not classified', 'Information', 'Warning', 'Average', 'High', 'Disaster']
ADDRESS = re.compile(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
LAB_ID = re.compile(r'lab-[A-Za-z0-9]{4,32}\Z')
MAX_RECIPIENTS = 20


def log(kind, **fields):
    print(json.dumps(dict(time=datetime.now(timezone.utc).isoformat(), kind=kind, **fields)), flush=True)


def private_directory(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid():
        raise ValueError('State/config directory must belong to the current user')
    os.chmod(directory, 0o700)


def validate(config):
    if not isinstance(config, dict):
        raise ValueError('Configuration must be an object')
    for field in ('api_url', 'api_token', 'sender', 'smtp_password'):
        if not isinstance(config.get(field), str):
            raise ValueError('Invalid configuration field: ' + field)
    if config.get('api_url') != 'http://127.0.0.1:8080/api_jsonrpc.php':
        raise ValueError('Only the local OPLA API endpoint is supported')
    host = config.get('host')
    if host is not None and (not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', host)):
        raise ValueError('Invalid technical host name')
    if not re.fullmatch(r'[A-Fa-f0-9]{64}', config.get('api_token', '')):
        raise ValueError('Expected a Zabbix API token of 64 hexadecimal characters')
    if not ADDRESS.fullmatch(config.get('sender', '')) or not config['sender'].lower().endswith('@gmail.com'):
        raise ValueError('Use the authenticated Gmail address as sender')
    recipients = config.get('recipients', [])
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise ValueError(f'Enter 1 to {MAX_RECIPIENTS} distinct recipient email addresses')
    if any(not isinstance(x, str) or not ADDRESS.fullmatch(x) for x in recipients):
        raise ValueError('Recipient list contains an invalid email address')
    if len({address.lower() for address in recipients}) != len(recipients):
        raise ValueError('Recipient email addresses must be unique')
    if not re.fullmatch(r'[A-Za-z0-9]{16}', config.get('smtp_password', '')):
        raise ValueError('Expected a 16-character Gmail app password')
    return config


def selected_lab_id():
    """Read the invoking user's atomically written lab selection safely."""
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(SELECTION, flags)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_size > 128):
            raise ValueError('Selected lab file has unsafe ownership, mode, or size')
        raw = os.read(fd, 129)
    finally:
        os.close(fd)
    try:
        value = raw.decode('ascii').strip()
    except UnicodeError:
        raise ValueError('Selected lab file is not ASCII') from None
    if not LAB_ID.fullmatch(value):
        raise ValueError('Selected lab file contains an invalid lab ID')
    try:
        root_info = LAB_ROOT.lstat()
    except FileNotFoundError:
        raise ValueError('OPLA lab root is unavailable or unsafe') from None
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
            or root_info.st_mode & 0o022):
        raise ValueError('OPLA lab root is unavailable or unsafe')
    lab_dir = LAB_ROOT / value
    try:
        lab_info = lab_dir.lstat()
    except FileNotFoundError:
        raise ValueError('Selected lab no longer exists; select an active lab first') from None
    if (not stat.S_ISDIR(lab_info.st_mode) or lab_info.st_uid != 0
            or lab_info.st_mode & 0o022):
        raise ValueError('Selected lab directory has unsafe identity')
    return value


def host_for_lab(lab_id):
    if not isinstance(lab_id, str) or not LAB_ID.fullmatch(lab_id):
        raise ValueError('Cannot derive Zabbix host from invalid lab ID')
    return 'opla-' + lab_id


def resolve_target(config, state_root=None):
    """Follow the selected lab; retain fixed-host behavior for legacy configs."""
    state_root = Path(state_root) if state_root is not None else STATE
    lab_id = selected_lab_id()
    if lab_id:
        host = host_for_lab(lab_id)
        legacy_queue = state_root / 'queue.sqlite3'
        # Adopt an existing fixed-host queue only when its configured host
        # exactly matches this selected lab. Queue.__init__ checks its durable
        # API/host scope before opening it for use.
        if config.get('host') == host and legacy_queue.is_file():
            queue_state = state_root
        else:
            queue_state = state_root / 'labs' / lab_id
        return {'lab_id': lab_id, 'host': host, 'state': queue_state}
    legacy_host = config.get('host')
    if legacy_host:
        return {'lab_id': None, 'host': legacy_host, 'state': state_root}
    raise ValueError('No lab selected; run opla lab select lab-XXXXXXXX')


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


def configure(filename):
    private_directory(filename.parent)
    if filename.exists() or filename.is_symlink():
        raise ValueError('Configuration already exists; edit it locally or choose another --config')
    lab_id = selected_lab_id()
    if not lab_id:
        raise ValueError('Select a lab first: opla lab select lab-XXXXXXXX')
    target_host = host_for_lab(lab_id)
    gmail = input('Gmail sender address: ').strip()
    raw_recipients = input(f'Recipient addresses, comma-separated (1-{MAX_RECIPIENTS}): ')
    recipients = [address.strip() for address in raw_recipients.split(',') if address.strip()]
    config = validate(dict(api_url='http://127.0.0.1:8080/api_jsonrpc.php', host=target_host,
                           api_token=getpass.getpass('Zabbix API token (hidden): ').strip(),
                           sender=gmail, recipients=recipients,
                           smtp_password=getpass.getpass('Gmail app password (hidden): ').replace(' ', '')))
    api = API(config)
    if not api.call('apiinfo.version', {}).startswith('7.0.'):
        raise ValueError('Zabbix 7.0 is required')
    api.host_id()
    api.call('problem.get', {'hostids': [api.host_id()], 'output': ['eventid'], 'limit': 1})
    api.events({'hostids': [api.host_id()], 'limit': 1})
    # New configs follow the selected lab at runtime rather than pinning one host.
    saved_config = {key: value for key, value in config.items() if key != 'host'}
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(saved_config, stream, indent=2)
        stream.write('\n')
    print(f'Saved private email config for {len(recipients)} recipient(s). Runtime target follows selected lab {lab_id}.')


def save_config(filename, config):
    fd, temporary = tempfile.mkstemp(prefix='.alerts.', dir=filename.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(config, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, filename)
        directory_fd = os.open(filename.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def update_recipients(filename):
    config = load_config(filename)
    raw_recipients = input(f'New complete recipient list, comma-separated (1-{MAX_RECIPIENTS}): ')
    config['recipients'] = [address.strip() for address in raw_recipients.split(',')
                            if address.strip()]
    validate(config)
    save_config(filename, config)
    print(f'Saved {len(config["recipients"])} recipients. Run alerts_service.py install to restart the worker.')


def update_api_token(filename):
    config = load_config(filename)
    token = getpass.getpass('New Zabbix API token (hidden): ').strip()
    candidate = dict(config, api_token=token)
    validate(candidate)
    target = resolve_target(config)
    target_config = dict(candidate, host=target['host'])
    api = API(target_config)
    if not api.call('apiinfo.version', {}).startswith('7.0.'):
        raise ValueError('Zabbix 7.0 is required')
    host_id = api.host_id()
    api.call('problem.get', {'hostids': [host_id], 'output': ['eventid'], 'limit': 1})
    api.events({'hostids': [host_id], 'limit': 1})
    save_config(filename, candidate)
    print('Validated and saved the API token. Run alerts_service.py install to restart the worker.')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['configure', 'recipients', 'api-token', 'run', 'test', 'status'])
    parser.add_argument('--config', type=Path, default=CONFIG)
    parser.add_argument('--state', type=Path, default=STATE)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if args.action == 'configure':
        configure(args.config)
        return
    if args.action == 'recipients':
        update_recipients(args.config)
        return
    if args.action == 'api-token':
        update_api_token(args.config)
        return
    config = load_config(args.config)
    if args.action == 'status':
        target = resolve_target(config, args.state)
        dbfile = (target['state'] / 'queue.sqlite3').absolute()
        print('Selected lab:', target['lab_id'] or 'legacy fixed host')
        print('Zabbix host:', target['host'])
        if not dbfile.exists():
            print('Queue has not been initialized')
            return
        db = sqlite3.connect(dbfile.as_uri() + '?mode=ro', uri=True)
        print('Pending/accepted by SMTP:', db.execute('SELECT sum(sent IS NULL),sum(sent IS NOT NULL) FROM jobs').fetchone())
        print('Poll state:', db.execute("SELECT * FROM meta WHERE key LIKE 'last_poll_%'").fetchall())
        for row in db.execute('SELECT id,eventid,kind,attempts,last_error FROM jobs WHERE sent IS NULL ORDER BY id LIMIT 20'):
            print(row)
        return
    state_root = args.state
    private_directory(state_root)
    with (state_root / 'worker.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Delivery worker already running; stop opla-alerts.service first')
        if args.action == 'test' or args.once:
            target = resolve_target(config, state_root)
            target_config = dict(config, host=target['host'])
            queue = Queue(target['state'], target_config)
            if args.action == 'test':
                event = dict(eventid='test-' + uuid.uuid4().hex, clock=str(int(time.time())),
                             severity='2', name='Контроль очереди OPLA alerts')
                with queue.db:
                    queue.add(event, 'TEST', target_config['recipients'])
            else:
                try:
                    poll(API(target_config), queue, target_config)
                    record_poll_result(queue, target_config, None, time.time())
                except Exception as error:
                    record_poll_result(queue, target_config, type(error).__name__, time.time())
            if args.action == 'test' or args.once:
                send_one_cycle(queue, target_config)
                return

        active_key = None
        active_target = None
        active_config = None
        active_queue = None
        inactive_target_error = None
        queues = {}
        inflight = {}
        last_poll = 0
        with ThreadPoolExecutor(max_workers=2) as executor:
            while True:
                try:
                    target = resolve_target(config, state_root)
                    target_key = (target['lab_id'], target['host'])
                    target_error = None
                except (ValueError, OSError) as error:
                    target = None
                    target_key = None
                    target_error = str(error)

                if target_key != active_key:
                    active_key = target_key
                    active_target = target
                    active_config = dict(config, host=target['host']) if target else None
                    if target:
                        active_queue = queues.get(target_key)
                        if active_queue is None:
                            active_queue = Queue(target['state'], active_config)
                            queues[target_key] = active_queue
                    else:
                        active_queue = None
                    last_poll = 0
                if target_error != inactive_target_error:
                    if target_error:
                        log('lab_target_unavailable', error=target_error)
                    inactive_target_error = target_error

                now = time.time()
                if active_queue is not None and now - last_poll >= 15:
                    try:
                        poll(API(active_config), active_queue, active_config)
                        record_poll_result(active_queue, active_config, None, time.time())
                    except Exception as error:
                        category = type(error).__name__
                        record_poll_result(active_queue, active_config, category, time.time())
                        log('api_poll_failed', lab=active_target['lab_id'], error=category)
                    last_poll = now

                for inflight_key, (job, future, job_queue, job_config) in list(inflight.items()):
                    if future.done():
                        try:
                            error = future.result()
                        except Exception:
                            error = 'delivery worker failed'
                        job_queue.complete(job, error, time.time())
                        del inflight[inflight_key]
                inflight_queues = {id(entry[2]) for entry in inflight.values()}
                for queue_key, old_queue in list(queues.items()):
                    if old_queue is not active_queue and id(old_queue) not in inflight_queues:
                        old_queue.db.close()
                        del queues[queue_key]
                if active_queue is not None:
                    for job in active_queue.due(time.time()):
                        inflight_key = (active_key, job['id'])
                        if len(inflight) < 2 and inflight_key not in inflight:
                            future = executor.submit(send, active_config, dict(job))
                            inflight[inflight_key] = (job, future, active_queue, active_config)
                time.sleep(1)


def send_one_cycle(queue, config):
    for job in queue.due(time.time()):
        queue.complete(job, send(config, dict(job)), time.time())
    print('One cycle completed; use status to inspect pending deliveries')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError) as error:
        raise SystemExit(str(error))
