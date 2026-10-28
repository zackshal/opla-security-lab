#!/usr/bin/env python3
"""Читаем state.env как данные, без выполнения shell-команд."""
import ipaddress
import os
from pathlib import Path
import re
import sys

def latest():
    files = list(Path('/var/lib/opla').glob('lab-*/state.env'))
    return str(max(files, key=lambda p:p.stat().st_mtime).parent) if files else ''

def load(directory):
    p=Path(directory).resolve()
    if p.parent != Path('/var/lib/opla') or not re.fullmatch(r'lab-[A-Za-z0-9]+',p.name):
        raise ValueError('Ожидается /var/lib/opla/lab-...')
    for item in [p, p/'state.env']:
        st=item.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('Состояние должно принадлежать root без записи для группы/остальных')
    d=dict(line.split('=',1) for line in (p/'state.env').read_text().splitlines() if '=' in line)
    if d['LAB_ID'] != p.name or not re.fullmatch(r'br-op[0-9]+', d['BRIDGE']):
        raise ValueError('Некорректное состояние стенда')
    net=ipaddress.ip_network(d['SUBNET'])
    if net.prefixlen != 29 or not net.subnet_of(ipaddress.ip_network('100.64.0.0/10')):
        raise ValueError('Некорректная подсеть')
    for k in ['GW','ATTACKER_IP','VICTIM_IP','CLIENT_IP']:
        if ipaddress.ip_address(d[k]) not in net: raise ValueError(k)
    mgmt_keys = ['MGMT_BRIDGE', 'MGMT_SUBNET', 'MGMT_GW',
                 'ATTACKER_MGMT_IP', 'VICTIM_MGMT_IP', 'CLIENT_MGMT_IP']
    present = [key in d for key in mgmt_keys]
    if any(present):
        if not all(present) or not re.fullmatch(r'br-op[0-9]+', d['MGMT_BRIDGE']) \
                or d['BRIDGE'] == d['MGMT_BRIDGE']:
            raise ValueError('Некорректное состояние management-интерфейса')
        mgmt_net=ipaddress.ip_network(d['MGMT_SUBNET'])
        if mgmt_net.prefixlen != 29 or not mgmt_net.subnet_of(ipaddress.ip_network('100.64.0.0/10')):
            raise ValueError('Некорректная management подсеть')
        if mgmt_net.overlaps(net):
            raise ValueError('Management и data подсети пересекаются')
        for k in mgmt_keys[2:]:
            if ipaddress.ip_address(d[k]) not in mgmt_net: raise ValueError(k)
    return d


def ssh_ip(directory, address):
    data = load(directory)
    mapping = {
        data['ATTACKER_IP']: data['ATTACKER_MGMT_IP'],
        data['VICTIM_IP']: data['VICTIM_MGMT_IP'],
        data['CLIENT_IP']: data['CLIENT_MGMT_IP'],
    }
    try:
        return mapping[address]
    except KeyError as exc:
        raise ValueError('SSH target must be a known lab guest address') from exc

if __name__=='__main__':
    try:
        if sys.argv[1:] == ['--latest']: print(latest())
        elif len(sys.argv) == 4 and sys.argv[2] == 'SSH_IP': print(ssh_ip(sys.argv[1], sys.argv[3]))
        else: print(load(sys.argv[1])[sys.argv[2]])
    except (ValueError,KeyError,OSError,IndexError) as e:
        sys.exit(f'Не удалось прочитать состояние: {e}')
