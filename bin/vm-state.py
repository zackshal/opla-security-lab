#!/usr/bin/env python3
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import sys
import stat
from qmp import QMP
from state import load

ROOT = Path(__file__).resolve().parents[1]
VMS = ('attacker', 'victim', 'client')

def tag(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,47}', value):
        raise argparse.ArgumentTypeError('Tag: 1..48 letters, digits, underscore, dot or dash')
    return value

def require_stopped_collector(lab):
    # QEMU lifecycle runs as root, while the collector is a user service.
    # Resolve the lab owner's persistent state from its protected SSH file.
    key_file = lab / 'known_hosts'
    info = key_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Cannot identify lab owner for collector lock check')
    try:
        owner_home = Path(pwd.getpwuid(info.st_uid).pw_dir)
    except KeyError as exc:
        raise RuntimeError('Unknown owner for lab SSH host-key file') from exc
    path = owner_home / '.local/state/opla/monitoring/runtime' / lab.name / 'collector.lock'
    try:
        fd=os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError('Unsafe monitoring collector lock; inspect before rollback') from exc
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Unsafe monitoring collector lock; inspect before rollback')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Stop collector before rollback: make monitoring-stop')
    finally:
        os.close(fd)

def main():
    p = argparse.ArgumentParser(description='QMP snapshots for newly launched OPLA VMs')
    p.add_argument('action', choices=['list', 'save', 'load', 'delete', 'status'])
    p.add_argument('--lab', required=True)
    p.add_argument('--vm', choices=[*VMS, 'all'], default='victim')
    p.add_argument('--tag', type=tag)
    p.add_argument('--confirm-rollback', action='store_true')
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('Run with sudo')
    load(args.lab)
    lab = Path(args.lab).resolve()
    if args.action in ['save', 'load', 'delete'] and not args.tag:
        p.error('--tag required')
    if args.action == 'load':
        if not args.confirm_rollback:
            p.error('--confirm-rollback required: disk/RAM state will rewind')
        require_stopped_collector(lab)
    with (lab / 'maintenance.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for vm in VMS if args.vm == 'all' else [args.vm]:
            path = lab / (vm + '-qmp.sock')
            if not path.exists():
                raise RuntimeError('No QMP socket: recreate this lab with the updated launcher')
            with QMP(path) as q:
                if args.action == 'status':
                    result = q.call('query-status')
                elif args.action == 'list':
                    result = q.hmp('info snapshots')
                else:
                    command = {'save': 'savevm', 'load': 'loadvm', 'delete': 'delvm'}[args.action]
                    if args.action == 'save':
                        existing = q.hmp('info snapshots')
                        if any(args.tag in line.split() for line in existing.splitlines()):
                            raise RuntimeError('Snapshot tag already exists; use a new tag')
                    result = q.hmp(command + ' ' + args.tag)
                    if result.strip():
                        raise RuntimeError('QEMU did not confirm snapshot operation: ' + result)
                    event = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                             'vm': vm, 'action': args.action, 'tag': args.tag,
                             'scope': 'one VM; external DB and other VMs not atomic'}
                    with (lab / 'snapshot-events.jsonl').open('a') as stream:
                        stream.write(json.dumps(event) + '\n')
            print(json.dumps({'vm': vm, 'result': result or 'ok'}))

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        sys.exit(str(error))
