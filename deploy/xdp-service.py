#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

PIN = Path('/sys/fs/bpf/opla-server')

def run(*args):
    return subprocess.check_output(args, text=True, timeout=30)

def current(interface):
    return json.loads(run('ip', '-j', 'link', 'show', 'dev', interface))[0].get('xdp', {})

def owned_id():
    if not (PIN/'program').exists():
        return None
    obj = json.loads(run('bpftool', '-j', 'prog', 'show', 'pinned', str(PIN/'program')))
    return (obj[0] if isinstance(obj, list) else obj)['id']

def ids(xdp):
    values = [xdp] + (xdp.get('attached') if isinstance(xdp.get('attached'), list) else [])
    return {int(v.get('prog', {}).get('id', v.get('prog_id', 0))) for v in values}

def active(xdp):
    return bool(xdp) and xdp.get('attached', 'off') not in ('off', 0)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['attach', 'detach'])
    p.add_argument('--interface', required=True)
    p.add_argument('--object', type=Path)
    a = p.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', a.interface):
        p.error('Invalid interface')
    link = current(a.interface)
    if a.action == 'detach':
        ident = owned_id()
        if active(link) and (ident is None or ident not in ids(link)):
            raise RuntimeError('Refuse to detach a different XDP program')
        if active(link):
            run('ip', 'link', 'set', 'dev', a.interface, 'xdp', 'off')
        if PIN.exists():
            shutil.rmtree(PIN)
        return
    if active(link):
        raise RuntimeError('Interface already has XDP; no automatic replacement')
    if a.object is None or not a.object.is_file():
        p.error('Compiled --object required')
    if PIN.exists():
        raise RuntimeError('Stale pins: inspect and explicitly detach before attach')
    (PIN/'maps').mkdir(parents=True)
    try:
        run('bpftool', 'prog', 'load', str(a.object), str(PIN/'program'), 'type', 'xdp', 'pinmaps', str(PIN/'maps'))
        run('ip', 'link', 'set', 'dev', a.interface, 'xdpdrv', 'pinned', str(PIN/'program'))
    except Exception:
        if not active(current(a.interface)):
            shutil.rmtree(PIN)
        raise

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
