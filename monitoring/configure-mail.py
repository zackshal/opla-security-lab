#!/usr/bin/env python3
import argparse
import getpass
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

spec = importlib.util.spec_from_file_location('opla_setup_mail', Path(__file__).with_name('setup.py'))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

def validate(config):
    required = ['server', 'port', 'sender', 'recipient', 'username', 'password', 'zabbix_user']
    if any(not config.get(k) for k in required):
        raise ValueError('Missing mail configuration fields')
    for key in ['sender', 'recipient']:
        if not re.fullmatch(r'[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+', config[key]):
            raise ValueError('Invalid ' + key)
    if config.get('security', 'starttls') not in ['starttls', 'tls']:
        raise ValueError('Verified TLS is required')
    if type(config['port']) is not int or not 1 <= config['port'] <= 65535:
        raise ValueError('Invalid SMTP port')
    if any('\n' in str(config[k]) or '\r' in str(config[k]) for k in required if k != 'password'):
        raise ValueError('Unexpected newline')
    return config

def configure(api, config):
    c = validate(config)
    users = api.call('user.get', {'filter': {'username': [c['zabbix_user']]}, 'selectMedias': 'extend'})
    groups = api.call('hostgroup.get', {'filter': {'name': ['OPLA Lab']}})
    if len(users) != 1 or len(groups) != 1:
        raise ValueError('Provision OPLA hosts and select one existing Zabbix user with host permissions')
    media = {'name': 'OPLA SMTP', 'type': 0, 'smtp_server': c['server'], 'smtp_port': c['port'],
             'smtp_email': c['sender'], 'smtp_helo': c.get('helo', 'opla.local'),
             'smtp_security': 1 if c.get('security', 'starttls') == 'starttls' else 2,
             'smtp_verify_peer': 1, 'smtp_verify_host': 1, 'smtp_authentication': 1,
             'username': c['username'], 'passwd': c['password'], 'status': 0,
             'message_format': 0, 'maxattempts': 3, 'attempt_interval': '30s'}
    found = api.call('mediatype.get', {'filter': {'name': ['OPLA SMTP']}})
    if found:
        mid = found[0]['mediatypeid']
        api.call('mediatype.update', dict(media, mediatypeid=mid))
    else:
        mid = api.call('mediatype.create', media)['mediatypeids'][0]
    fields = ['mediatypeid', 'sendto', 'active', 'severity', 'period']
    other = [{k: m[k] for k in fields if k in m} for m in users[0].get('medias', [])
             if str(m['mediatypeid']) != str(mid)]
    other.append({'mediatypeid': mid, 'sendto': [c['recipient']], 'active': 0,
                  'severity': 60, 'period': '1-7,00:00-24:00'})
    uid = users[0]['userid']
    api.call('user.update', {'userid': uid, 'medias': other})
    def operation(recovery=False):
        message = {'default_msg': 0, 'mediatypeid': mid,
                   'subject': ('[OPLA recovery] ' if recovery else '[OPLA problem] ') + '{EVENT.NAME}',
                   'message': 'Host: {HOST.NAME}\nEvent: {EVENT.ID}\nProblem: {EVENT.NAME}\nSeverity: {EVENT.SEVERITY}\nTime: {EVENT.DATE} {EVENT.TIME}'}
        result = {'operationtype': 0, 'opmessage': message, 'opmessage_usr': [{'userid': uid}]}
        if not recovery:
            result.update(esc_step_from=1, esc_step_to=1)
        return result
    params = {'name': 'OPLA email notifications', 'eventsource': 0, 'status': 0,
              'esc_period': '1m', 'filter': {'evaltype': 1, 'conditions': [
                  {'conditiontype': 0, 'operator': 0, 'value': groups[0]['groupid']},
                  {'conditiontype': 4, 'operator': 5, 'value': '2'}]},
              'operations': [operation()], 'recovery_operations': [operation(True)]}
    actions = api.call('action.get', {'filter': {'name': [params['name']]}})
    if actions:
        api.call('action.update', dict(params, actionid=actions[0]['actionid']))
    else:
        api.call('action.create', params)
    return {'recipient': c['recipient'], 'user': c['zabbix_user'], 'delivery': 'not tested'}

def main():
    p = argparse.ArgumentParser(description='Configure native Zabbix SMTP and problem/recovery action')
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--api-password-env', action='store_true')
    a = p.parse_args()
    st = a.config.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        p.error('Configuration must be owned by current user with mode 0600')
    c = validate(json.loads(a.config.read_text()))
    if not a.apply:
        print(json.dumps({'recipient': c['recipient'], 'smtp': c['server'], 'action': 'dry run; add --apply'}))
        return
    api = setup.API('http://127.0.0.1:8080/api_jsonrpc.php')
    if not api.call('apiinfo.version', {}).startswith('7.0.'):
        p.error('Zabbix 7.0 required')
    user = 'Admin' if a.api_password_env else (input('Zabbix administrator [Admin]: ').strip() or 'Admin')
    password = os.environ.pop('ZABBIX_PASSWORD') if a.api_password_env else getpass.getpass('Zabbix password: ')
    api.auth = api.call('user.login', {'username': user, 'password': password})
    try:
        print(json.dumps(configure(api, c)))
    finally:
        api.call('user.logout', [])

if __name__ == '__main__':
    main()
