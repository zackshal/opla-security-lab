#!/usr/bin/env python3
"""Читаем state.env как данные, без выполнения shell-команд."""
import ipaddress
import os
from pathlib import Path
import re
import sys

def latest():
    files = list(Path('/run/opla').glob('lab-*/state.env'))
    return str(max(files, key=lambda p:p.stat().st_mtime).parent) if files else ''

def load(directory):
    p=Path(directory).resolve()
    if p.parent != Path('/run/opla') or not re.fullmatch(r'lab-[A-Za-z0-9]+',p.name):
        raise ValueError('Ожидается /run/opla/lab-...')
    for item in [p, p/'state.env']:
        st=item.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('Состояние должно принадлежать root без записи для группы/остальных')
    d=dict(line.split('=',1) for line in (p/'state.env').read_text().splitlines() if '=' in line)
    if d['LAB_ID'] != p.name or not re.fullmatch(r'br-op[0-9]+',d['BRIDGE']):
        raise ValueError('Некорректное состояние стенда')
    net=ipaddress.ip_network(d['SUBNET'])
    if net.prefixlen != 29 or not net.subnet_of(ipaddress.ip_network('100.64.0.0/10')):
        raise ValueError('Некорректная подсеть')
    for k in ['GW','ATTACKER_IP','VICTIM_IP','CLIENT_IP']:
        if ipaddress.ip_address(d[k]) not in net: raise ValueError(k)
    return d

if __name__=='__main__':
    try:
        if sys.argv[1:] == ['--latest']: print(latest())
        else: print(load(sys.argv[1])[sys.argv[2]])
    except (ValueError,KeyError,OSError,IndexError) as e:
        sys.exit(f'Не удалось прочитать состояние: {e}')
