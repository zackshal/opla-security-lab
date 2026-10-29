#!/usr/bin/env python3
"""Read-only evidence audit before ACTIVE failed-creation recovery.

This command NEVER stops units, changes network interfaces, or removes files.
A creation receipt is an intent record, not exclusive kernel ownership proof.
"""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

rollback = load('v594_rollback', 'opla-creation-rollback.py')
prune = rollback.prune
registry = rollback.registry
Blocked = rollback.Blocked
process_runtime = load('v594_process', 'opla_process.py')


DEFAULT_PROBE_TIMEOUT = 10.0
MAX_PROBE_OUTPUT_BYTES = 128 * 1024


def run(args, *, timeout=DEFAULT_PROBE_TIMEOUT, runner=None):
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("recovery probe timeout must be positive")
    if runner is None:
        return process_runtime.run_bounded(
            args, timeout=timeout, max_output_bytes=MAX_PROBE_OUTPUT_BYTES)
    return runner(args, capture_output=True, text=True, check=False, timeout=timeout)


def require(args, runner):
    p = runner(args)
    if getattr(p, 'cleanup_error', None):
        raise Blocked('probe cleanup is uncertain: ' + ' '.join(args))
    if getattr(p, 'output_limited', False):
        raise Blocked('probe output exceeded safety limit: ' + ' '.join(args))
    if p.returncode:
        raise Blocked('probe failed: ' + ' '.join(args) + ': ' + p.stderr.strip())
    return p.stdout


def verify_receipt(root, lab):
    root = prune.safe_root(root)
    if not registry.VALID.fullmatch(lab):
        raise Blocked('invalid laboratory ID')
    rd = root / 'registry'
    rf = rd / (lab + '.json')
    if rd.is_symlink() or not rd.is_dir() or rf.is_symlink() or not rf.is_file():
        raise Blocked('missing or unsafe creation receipt')
    record = json.loads(rf.read_text(encoding='utf-8'))
    expected = registry.receipt(root, lab, 'creating')
    if any(record.get(k) != expected[k] for k in ('schema','lab_id','lab_dir','phase','resources')):
        raise Blocked('creation receipt differs from registry/state')
    claimed = {(r['kind'], r['name']) for r in expected['resources']}
    for item in rd.iterdir():
        if item == rf: continue
        if item.is_symlink() or not item.is_file() or item.suffix != '.json' or not registry.VALID.fullmatch(item.stem):
            raise Blocked('unsafe sibling receipt')
        other = json.loads(item.read_text(encoding='utf-8'))
        if other.get('phase') not in ('creating','ready'):
            raise Blocked('invalid sibling phase')
        calculated = registry.receipt(root, item.stem, other['phase'])
        if any(other.get(k) != calculated[k] for k in ('schema','lab_id','lab_dir','phase','resources')):
            raise Blocked('invalid sibling receipt')
        if claimed & {(r['kind'], r['name']) for r in calculated['resources']}:
            raise Blocked('shared host resources with ' + item.stem)
    return root, expected, registry.state_of(root, lab)


def audit(root, lab, runner=run):
    root, expected, state = verify_receipt(root, lab)
    bridge = state['BRIDGE']
    table = 'opla_' + lab.replace('-', '_')
    report = {'lab':lab, 'phase':'creating', 'checks':[],
              'execution_allowed':False, 'operation':'active_creation_recovery_preflight'}
    # Fail closed on unexpected files, symlinks, mounts and hardlinks.
    # QEMU sockets are expected only at the lab root, not in nested directories.
    from_socket = {f'{role}-{kind}.sock' for role in ('attacker','victim','client') for kind in ('qmp','console')}
    import stat
    for base, dirs, files in os.walk(root/lab, followlinks=False):
        for name in dirs+files:
            entry=Path(base)/name
            s=entry.lstat()
            if stat.S_ISLNK(s.st_mode) or entry.is_mount() or (stat.S_ISREG(s.st_mode) and s.st_nlink != 1):
                raise Blocked('unsafe lab tree entry: '+str(entry))
            if stat.S_ISSOCK(s.st_mode):
                if entry.parent != root/lab or name not in from_socket:
                    raise Blocked('unexpected lab socket')
            elif not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)):
                raise Blocked('unexpected special file in lab tree')
    report['checks'].append('lab tree and sibling receipts matched')
    # Unit inspections are NOT treated as proof of ownership. Require recognizable
    # ExecStart for every active unit, with exact lab path and expected binary.
    for role in ('attacker','victim','client'):
        unit=f'qemu-{lab}-{role}.service'
        raw=require(['systemctl','show',unit,'-p','LoadState','-p','ActiveState','-p','MainPID','-p','ExecStart','--no-pager'],runner)
        if 'ActiveState=active' in raw or 'ActiveState=activating' in raw:
            if ('qemu-system-x86_64' not in raw or str(root/lab/role/'disk.qcow2') not in raw or 'MainPID=0' in raw):
                raise Blocked('active QEMU identity mismatch: '+unit)
        report['checks'].append(unit+': inspected')
    unit=f'dhcp-{lab}.service'
    raw=require(['systemctl','show',unit,'-p','LoadState','-p','ActiveState','-p','MainPID','-p','ExecStart','--no-pager'],runner)
    if 'ActiveState=active' in raw or 'ActiveState=activating' in raw:
        if ('dnsmasq' not in raw or str(root/lab/'dnsmasq.conf') not in raw or 'MainPID=0' in raw):
            raise Blocked('active DHCP identity mismatch')
    report['checks'].append(unit+': inspected')
    # Query link inventory to distinguish absent devices from probe failures.
    raw=require(['ip','-o','link','show'],runner)
    names=set()
    for line in raw.splitlines():
        parts=line.split(':',2)
        if len(parts)>1:names.add(parts[1].strip().split('@')[0])
    taps={'op'+bridge.removeprefix('br-op')+s for s in 'avc'}
    if bridge in names:
        address=require(['ip','-o','-4','addr','show','dev',bridge],runner)
        if state.get('GW','')+'/29' not in address:
            raise Blocked('bridge address mismatch')
        members=require(['ip','-o','link','show','master',bridge],runner)
        for line in members.splitlines():
            parts=line.split(':',2)
            if len(parts)<2 or parts[1].strip().split('@')[0] not in taps:
                raise Blocked('foreign bridge member')
    for tap in sorted(taps & names):
        detail=require(['ip','-o','link','show','dev',tap],runner)
        if 'master '+bridge not in detail:
            raise Blocked('TAP master differs: '+tap)
    report['checks'].append('bridge and TAP identities inspected')
    probe=runner(['nft','list','table','inet',table])
    if getattr(probe, 'cleanup_error', None):
        raise Blocked('nft probe cleanup is uncertain')
    if getattr(probe, 'output_limited', False):
        raise Blocked('nft probe output exceeded safety limit')
    if probe.returncode == 0:
        # Reuse strict *exact policy* check from lifecycle implementation.
        required={
          f'table inet {table}', 'chain forward', 'type filter hook forward priority -20; policy accept;',
          f'iifname "{bridge}" oifname != "{bridge}" drop',f'oifname "{bridge}" iifname != "{bridge}" drop',
          'chain input','type filter hook input priority -20; policy accept;',
          f'iifname "{bridge}" ct state established,related accept',
          f'iifname "{bridge}" udp dport 67 accept',f'iifname "{bridge}" drop'}
        actual=[]
        for line in probe.stdout.splitlines():
            line=line.strip()
            if not line or line in ('{','}'):continue
            if line.endswith(' {'):line=line[:-2].rstrip()
            actual.append(line)
        if len(actual)!=len(required) or set(actual)!=required:
            raise Blocked('nft policy mismatch')
    elif probe.returncode!=1 or not re.search(r'no such file|does not exist',probe.stderr,re.I):
        raise Blocked('nft probe failure')
    report['checks'].append('nft policy inspected')
    # Collect evidence but never authorize execution: proc/fd enumeration and
    # transactional shutdown/rollback are still pending.
    report['next_step']='human review; automated active cleanup remains disabled'
    return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',required=True)
    p.add_argument('--root',default='/var/lib/opla')
    args=p.parse_args(argv)
    if os.geteuid()!=0:p.error('root required')
    try:
        print(json.dumps(audit(args.root,args.lab),indent=2))
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,
            subprocess.SubprocessError) as exc:
        print('BLOCKED:',exc,file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':sys.exit(main())
