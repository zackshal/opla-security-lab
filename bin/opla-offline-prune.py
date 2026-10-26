#!/usr/bin/env python3
"""Conservative offline deletion of one previously recorded OPLA laboratory.

No VM/bridge/tap/systemd/nft modifications. If ANY host resource is present,
unknown or unprobeable, refuse deletion. Run only with explicitly typed lab ID.
Requires trusted root-owned /var/lib/opla and no concurrent lab management.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent

def load(module, filename):
    spec = importlib.util.spec_from_file_location(module, HERE / filename)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

registry = load('v58registry', 'opla-registry.py')

class Blocked(RuntimeError):
    pass

def safe_root(root):
    root = Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise Blocked('root missing, relative or symlink')
    s = root.lstat()
    if s.st_uid != 0 or s.st_mode & 0o022:
        raise Blocked('root must be root-owned and not group/world writable')
    return root

def run_probe(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked('unavailable probe: ' + argv[0])
    return p

def host_absent(resources, runner=run_probe):
    """Fail closed: unexpected command exit codes and unknown services block."""
    reasons=[]
    for entry in resources:
        kind, name = entry['kind'], entry['name']
        if kind in ('bridge', 'tap'):
            p=runner(['ip','-o','link','show','dev',name])
            # ip exits 1 when interface absent; other codes may indicate failure.
            if p.returncode != 1 or 'does not exist' not in (p.stderr + p.stdout).lower():
                reasons.append(f'{kind} {name}: present or status unverified')
        elif kind == 'nft_table':
            p=runner(['nft','-a','list','tables'])
            if p.returncode != 0:
                reasons.append('nftables listing failed')
            elif any(line.strip().split()[:3] == ['table','inet',name] for line in p.stdout.splitlines()):
                reasons.append(f'nft table {name}: present')
        elif kind in ('qemu_unit','dhcp_unit'):
            p=runner(['systemctl','show',name,'--property=ActiveState,LoadState,MainPID','--no-pager'])
            if p.returncode != 0:
                reasons.append(f'unit {name}: cannot inspect')
                continue
            kv=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
            if kv.get('ActiveState') not in ('inactive','failed') or kv.get('MainPID') != '0' or kv.get('LoadState') not in ('not-found','loaded'):
                reasons.append(f'unit {name}: active or unknown')
        elif kind not in ('lab_directory','qcow2','cloud_init_iso'):
            reasons.append(f'unsupported resource kind {kind}')
    return reasons

def local_tree_safe(root, lab):
    path=root/lab
    if path.is_symlink() or not path.is_dir() or path.is_mount():
        raise Blocked('lab path is symlink, missing or mount')
    for parent, dirs, files in os.walk(path, topdown=True, followlinks=False):
        for name in dirs + files:
            p=Path(parent)/name
            st=p.lstat()
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise Blocked('nonregular file or symlink in lab tree: '+str(p))
            if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
                raise Blocked('hardlinked file in lab tree: '+str(p))
            if p.is_mount():
                raise Blocked('mountpoint inside lab: '+str(p))
    return path

def check(root, lab, runner=run_probe):
    root=Path(root)
    if not registry.VALID.fullmatch(lab):
        raise Blocked('invalid lab ID')
    safe_root(root)
    regdir=root/'registry'
    if regdir.is_symlink():
        raise Blocked('unsafe registry: symbolic link')
    if not regdir.exists():
        raise Blocked('registry not initialized: no laboratory receipts exist')
    if not regdir.is_dir():
        raise Blocked('unsafe registry: path is not a directory')
    receipt_file=regdir/(lab+'.json')
    if receipt_file.is_symlink():
        raise Blocked('unsafe receipt: symbolic link')
    if not receipt_file.is_file():
        raise Blocked(f'no registry receipt for {lab}; legacy or deleted laboratory cannot be pruned automatically')
    record=json.loads(receipt_file.read_text())
    if record.get('schema') != 1 or record.get('lab_id') != lab or record.get('phase') != 'ready':
        raise Blocked('receipt incomplete or invalid')
    expected=registry.receipt(root,lab,'ready')
    if record.get('lab_dir') != expected['lab_dir'] or record.get('resources') != expected['resources']:
        raise Blocked('receipt does not match current state')
    # All other receipts must be valid; otherwise exclusivity cannot be established.
    for other in regdir.iterdir():
        if other == receipt_file: continue
        if other.is_symlink() or not other.is_file() or not other.name.endswith('.json'):
            raise Blocked('unknown registry file')
        old=json.loads(other.read_text())
        if old.get('schema') != 1 or old.get('lab_id') != other.stem:
            raise Blocked('invalid peer registry receipt')
        try:
            r=registry.receipt(root,other.stem,old.get('phase','creating'))
        except (ValueError,OSError):
            raise Blocked('unverifiable peer registry receipt')
        if old.get('resources') != r['resources']:
            raise Blocked('peer receipt mismatch')
        own={(x['kind'],x['name']) for x in expected['resources']}
        peer={(x['kind'],x['name']) for x in r['resources']}
        if own & peer: raise Blocked('resource collision with '+other.stem)
    local_tree_safe(root,lab)
    # VM may have been launched outside the expected systemd unit. Check /proc
    # for a live QEMU command line referencing any managed image; inaccessible
    # process metadata also blocks deletion rather than guessing.
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            raw=(proc/'cmdline').read_bytes()
        except FileNotFoundError:
            continue
        except (OSError, PermissionError):
            raise Blocked('cannot inspect live process list')
        if b'qemu-system' in raw and str(root/lab).encode() in raw:
            raise Blocked('QEMU still references lab path: PID '+proc.name)
    reasons=host_absent(expected['resources'],runner)
    if reasons: raise Blocked('; '.join(reasons))
    return {'lab':lab,'directory':str(root/lab),'resources':len(expected['resources']),'mode':'offline_only'}

def write_journal(root, lab, outcome, detail):
    operations=root/'operations'
    if operations.is_symlink(): raise Blocked('unsafe journal directory')
    operations.mkdir(mode=0o700,exist_ok=True)
    if operations.stat().st_mode & 0o022: raise Blocked('unsafe journal permissions')
    journal=operations/'lab-cleanup.jsonl'
    payload={'schema':2,'timestamp_utc':datetime.now(timezone.utc).isoformat(), 'lab':lab,
             'operation':'offline_prune','outcome':outcome,'detail':detail}
    fd=os.open(journal,os.O_APPEND|os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (st.st_mode & 0o077):
            raise Blocked('unsafe journal file')
        os.write(fd,(json.dumps(payload,sort_keys=True)+'\n').encode())
        os.fsync(fd)
    finally: os.close(fd)

def execute(root, lab, confirm, runner=run_probe, lock_held=False):
    root=safe_root(root)
    if confirm != f'DELETE-OFFLINE:{lab}': raise Blocked('confirmation mismatch')
    lock=root/'.opla-prune.lock'
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode): raise Blocked('unsafe lock')
        if not lock_held:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        report=check(root,lab,runner)
        write_journal(root,lab,'executing',report)
        # No host resources are touched. This only deletes lab files and receipt.
        # Recheck before deletion (still requires serialized OPLA lab lifecycle).
        check(root,lab,runner)
        shutil.rmtree(root/lab)
        (root/'registry'/(lab+'.json')).unlink()
        write_journal(root,lab,'completed',report)
        return report
    except Exception as e:
        try: write_journal(root,lab,'failed',str(e))
        except Exception: pass
        raise
    finally:
        os.close(fd)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('plan','execute'))
    p.add_argument('--root',default='/var/lib/opla')
    p.add_argument('--lab',required=True)
    p.add_argument('--confirm',default='')
    a=p.parse_args(argv)
    try:
        result=check(a.root,a.lab) if a.action=='plan' else execute(a.root,a.lab,a.confirm)
        print(json.dumps({'status':'eligible' if a.action=='plan' else 'completed',**result},indent=2))
    except (Blocked,ValueError,OSError,KeyError,json.JSONDecodeError) as e:
        print('BLOCKED:',str(e),file=sys.stderr)
        return 2
    return 0

if __name__=='__main__': sys.exit(main())
