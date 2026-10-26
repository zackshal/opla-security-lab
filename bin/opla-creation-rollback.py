#!/usr/bin/env python3
"""Verify and remove an *offline* failed-create lab (receipt phase=creating).

Never stops QEMU/DHCP, removes network devices or nftables, and never cleans
an unregistered lab. A partially active failed creation is BLOCKED for review.
Only OPLA's private lab directory and corresponding creation receipt are removed.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prune = load('opla_rollback_prune', 'opla-offline-prune.py')
registry = prune.registry
Blocked = prune.Blocked


def verify(root, lab, runner=None):
    """Fail closed unless all declared host resources are absent."""
    root = prune.safe_root(root)
    if not registry.VALID.fullmatch(lab):
        raise Blocked('invalid laboratory ID')
    rd = root / 'registry'
    rf = rd / (lab + '.json')
    if rd.is_symlink() or not rd.is_dir() or rf.is_symlink() or not rf.is_file():
        raise Blocked('missing or unsafe creation receipt')
    record = json.loads(rf.read_text(encoding='utf-8'))
    expected = registry.receipt(root, lab, 'creating')
    if any(record.get(k) != expected[k] for k in ('schema', 'lab_id', 'lab_dir', 'phase', 'resources')):
        raise Blocked('receipt mismatch or not in creating phase')
    owned = {(item['kind'], item['name']) for item in expected['resources']}
    for other in rd.iterdir():
        if other == rf:
            continue
        if other.is_symlink() or not other.is_file() or not registry.VALID.fullmatch(other.stem) or other.suffix != '.json':
            raise Blocked('unsafe sibling receipt')
        sibling = json.loads(other.read_text(encoding='utf-8'))
        if sibling.get('phase') not in ('ready', 'creating'):
            raise Blocked('unknown sibling phase')
        sibling_expected = registry.receipt(root, other.stem, sibling['phase'])
        if any(sibling.get(k) != sibling_expected[k] for k in ('schema', 'lab_id', 'lab_dir', 'resources')):
            raise Blocked('invalid sibling receipt')
        if owned & {(item['kind'], item['name']) for item in sibling_expected['resources']}:
            raise Blocked('resource collision with ' + other.stem)
    # Reject links, sockets, mounted directories and hardlinks before deletion.
    prune.local_tree_safe(root, lab)
    target = str(root / lab).encode()
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            cmd = (proc / 'cmdline').read_bytes()
        except FileNotFoundError:
            continue
        except OSError:
            raise Blocked('cannot inspect process list')
        if target in cmd:
            raise Blocked('live process references the laboratory: PID ' + proc.name)
    # A failure to query ip/systemd/nft is never interpreted as absence.
    errors = prune.host_absent(expected['resources'], runner or prune.run_probe)
    if errors:
        raise Blocked('host resources still exist or cannot be verified: ' + '; '.join(errors))
    return {'lab': lab, 'directory': str(root / lab), 'phase': 'creating', 'host_resources': 'absent'}


def lock_is_safe(fd):
    """Require trusted root-owned, private, single-link lifecycle lock."""
    st = os.fstat(fd)
    return (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
            st.st_nlink == 1 and not st.st_mode & 0o022)

def execute(root, lab, confirm, runner=None):
    root = prune.safe_root(root)
    if confirm != 'ROLLBACK-CREATION:' + lab:
        raise Blocked('confirmation must be ROLLBACK-CREATION:' + lab)
    lock = root / '.opla-prune.lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not lock_is_safe(fd):
            raise Blocked('unsafe global lifecycle lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = verify(root, lab, runner)
        prune.write_journal(root, lab, 'planned', {'operation': 'creation_rollback', **report})
        # Recheck immediately before removing local files. All writers using
        # lifecycle lock are serialized; unrelated root processes cannot be.
        verify(root, lab, runner)
        prune.write_journal(root, lab, 'executing', {'operation': 'creation_rollback', **report})
        try:
            shutil.rmtree(root / lab)
            (root / 'registry' / (lab + '.json')).unlink()
            prune.write_journal(root, lab, 'completed', {'operation': 'creation_rollback', **report})
        except Exception as exc:
            try:
                prune.write_journal(root, lab, 'failed', {'operation': 'creation_rollback', 'error': str(exc)})
            except Exception:
                pass
            raise
        return report
    finally:
        os.close(fd)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=('plan', 'execute'))
    ap.add_argument('--root', default='/var/lib/opla')
    ap.add_argument('--lab', required=True)
    ap.add_argument('--confirm', default='')
    args = ap.parse_args(argv)
    if os.geteuid() != 0:
        ap.error('requires root')
    try:
        result = verify(args.root, args.lab) if args.action == 'plan' else execute(args.root, args.lab, args.confirm)
        print(json.dumps({'status': 'eligible_offline_only' if args.action == 'plan' else 'completed', **result}, indent=2))
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as exc:
        print('BLOCKED:', exc, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
