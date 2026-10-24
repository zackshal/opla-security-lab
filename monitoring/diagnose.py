#!/usr/bin/env python3
"""Проверяем настройки и приём каждого показателя отдельно. Запуск на хосте."""
import argparse
import fcntl
import getpass
import json
import sys
import time
from pathlib import Path

R = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(R / 'bin'))
from state import load
from bridge import METRICS, collect, send
from setup import API
from catalog import item_key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lab', required=True)
    args = parser.parse_args()
    state = load(args.lab)
    name = 'opla-' + state['LAB_ID']
    runtime = R / 'monitoring/runtime' / state['LAB_ID']
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime / 'collector.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.exit('Сначала make monitoring-stop: диагностика посылает контрольный снимок.')
        api = API('http://127.0.0.1:8080/api_jsonrpc.php')
        username = input('Zabbix user [Admin]: ').strip() or 'Admin'
        api.auth = api.call('user.login', {'username': username, 'password': getpass.getpass('Zabbix password: ')})
        try:
            hosts = api.call('host.get', {'filter': {'host': [name]}, 'output': ['hostid', 'host', 'status']})
            if not hosts:
                sys.exit('Узел отсутствует: make monitoring-configure')
            print('HOST', json.dumps(hosts[0], ensure_ascii=False))
            items = api.call('item.get', {'hostids': [hosts[0]['hostid']],
                'output': ['key_', 'type', 'value_type', 'status', 'state', 'error', 'lastclock', 'trapper_hosts'],
                'selectPreprocessing': 'extend'})
            for item in sorted(items, key=lambda x: x['key_']):
                if item['key_'].startswith(('xdp.', 'http.', 'net.')):
                    print('ITEM', json.dumps(item, ensure_ascii=False))
            data = collect(state['VICTIM_IP'], args.lab)
            values = {item_key(k): str(data[k]) for k in METRICS}
            values['xdp.mode'] = data['mode']
            values['xdp.events'] = json.dumps({'event': 'diagnostic_probe', 'metrics': data})
            failed = []
            for key, value in values.items():
                try:
                    send([{'host': name, 'key': key, 'value': value, 'clock': int(time.time())}])
                    print('ACCEPTED ' + key)
                except (OSError, ValueError) as error:
                    failed.append(key)
                    print('FAILED ' + key + ': ' + str(error))
            return int(bool(failed))
        finally:
            api.call('user.logout', [])


if __name__ == '__main__':
    sys.exit(main())
