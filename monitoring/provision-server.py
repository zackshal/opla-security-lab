#!/usr/bin/env python3
import argparse
import json
import os
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('provision_server_setup', Path(__file__).with_name('setup.py'))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', required=True)
    a = p.parse_args()
    api = setup.API('http://127.0.0.1:8080/api_jsonrpc.php')
    if not api.call('apiinfo.version', {}).startswith('7.0.'):
        raise ValueError('Zabbix 7.0 required')
    api.auth = api.call('user.login', {'username': 'Admin', 'password': os.environ.pop('ZABBIX_PASSWORD')})
    try:
        result = setup.provision(api, a.host)
        print(json.dumps({'host': a.host, 'items': len(result['items'])+len(result['rates'])}))
    finally:
        api.call('user.logout', [])

if __name__ == '__main__':
    main()
