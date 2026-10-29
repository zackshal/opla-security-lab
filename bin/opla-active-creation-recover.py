#!/usr/bin/env python3
"""Explicit, fail-closed active recovery of an incomplete OPLA lab.

Requires phase=creating, global lifecycle lock and exact confirmation. No
SIGKILL, Docker operations, shared monitoring changes, or shell cleanup.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

preflight = load('v595_preflight', 'opla-active-recovery-plan.py')
rollback = preflight.rollback
prune = rollback.prune
lifecycle = load('v595_lifecycle', 'lab-lifecycle.py')
secure = load('v595_secure', 'opla-secure-lab-delete.py')
Blocked = rollback.Blocked

ROLES = ('attacker', 'victim', 'client')


def process_starttime(stat_path):
    """Return Linux proc stat starttime, parsing comm fields with parentheses."""
    raw = Path(stat_path).read_text(encoding='ascii')
    closing = raw.rfind(')')
    if closing < 0:
        raise Blocked('malformed proc stat identity')
    fields = raw[closing + 1:].split()
    # The tail begins at field 3 (state); starttime is field 22 (index 19).
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise Blocked('malformed proc stat starttime')
    return fields[19]

def process_evidence(root, lab, *, runner=None, proc_root=Path('/proc')):
    """Fail closed when another process has any lab file open or wrong PID.

    Checks command lines and /proc fd symlink targets. PID reuse is checked
    again before mutation. Unknown /proc access is not interpreted as absence.
    """
    base = str(root / lab)
    runner = preflight.run if runner is None else runner
    proc_root = Path(proc_root)
    trusted = {}
    for role in ROLES:
        unit = f'qemu-{lab}-{role}.service'
        trusted[unit] = (f'qemu-system-x86_64', base + f'/{role}/disk.qcow2')
    trusted[f'dhcp-{lab}.service'] = ('dnsmasq', base + '/dnsmasq.conf')
    pids = {}
    for unit, (binary, marker) in trusted.items():
        raw = preflight.require(['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID', '--no-pager'], runner)
        data = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        if data.get('ActiveState') not in ('active','inactive','failed','activating','deactivating'):
            raise Blocked('unknown service status: ' + unit)
        if data['ActiveState'] in ('activating', 'deactivating'):
            raise Blocked('unit is transitioning: ' + unit)
        pid = data.get('MainPID', '')
        if not pid.isdecimal():
            raise Blocked('unparseable systemd PID: ' + unit)
        if data['ActiveState'] == 'active':
            if int(pid) == 0:
                raise Blocked('active unit without PID: ' + unit)
            starttime = process_starttime(proc_root / pid / 'stat')
            cmd = (proc_root / pid / 'cmdline').read_bytes().split(b'\x00')
            exe = os.readlink(proc_root / pid / 'exe')
            cgroup = (proc_root / pid / 'cgroup').read_text()
            paths = [line.split(':', 2)[-1].split('/') for line in cgroup.splitlines()]
            marker_matches = any(
                argument == marker.encode()
                or argument == ('--conf-file=' + marker).encode()
                or argument.startswith(('file=' + marker + ',').encode())
                for argument in cmd)
            if (Path(exe).name != binary or not marker_matches or
                    not any(unit in path for path in paths)):
                raise Blocked('process identity mismatch: ' + unit)
            if process_starttime(proc_root / pid / 'stat') != starttime:
                raise Blocked('process identity changed during inspection: ' + unit)
            if int(pid) in pids:
                raise Blocked('systemd units share PID: ' + unit)
            pids[int(pid)] = (unit, starttime)
        elif int(pid) != 0:
            raise Blocked('inactive unit retains PID: ' + unit)
    # Require that every process with this lab in cmdline or open fd is tracked.
    # Do not use /proc/<pid>/fd symlink alone for ownership: all references must
    # belong to independently verified systemd PIDs.
    for proc in proc_root.iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            pid = int(proc.name)
            starttime = process_starttime(proc / 'stat')
            if pid in pids and pids[pid][1] != starttime:
                raise Blocked('systemd PID was reused: ' + proc.name)
            cmd = (proc / 'cmdline').read_bytes()
            fd = proc / 'fd'
            paths = []
            for item in fd.iterdir():
                try:
                    paths.append(os.readlink(item))
                except FileNotFoundError:
                    continue
            for marker in ('cwd', 'root'):
                try:
                    paths.append(os.readlink(proc / marker))
                except FileNotFoundError:
                    continue
            references = base.encode() in cmd or any(p == base or p.startswith(base + '/') for p in paths)
            if process_starttime(proc / 'stat') != starttime:
                raise Blocked('process identity changed during FD inspection: ' + proc.name)
            if references and pid not in pids:
                raise Blocked('untracked process references lab: PID ' + proc.name)
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise Blocked('cannot inspect proc references: ' + proc.name) from exc
        except OSError as exc:
            raise Blocked('cannot inspect proc references: ' + proc.name) from exc
    return pids


def locked_recover(root, lab, confirm, *, audit=preflight.audit,
                   evidence=process_evidence, stop=None, offline=None,
                   verify_policies=None):
    """Integration hooks are injectable for tests, not CLI options."""
    root = prune.safe_root(root)
    if confirm != 'RECOVER-CREATION:' + lab:
        raise Blocked('confirmation must be RECOVER-CREATION:' + lab)
    if not preflight.registry.VALID.fullmatch(lab):
        raise Blocked('invalid lab ID')
    lf = root / '.opla-prune.lock'
    descriptor = os.open(lf, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not rollback.lock_is_safe(descriptor):
            raise Blocked('unsafe lifecycle lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = audit(root, lab)
        evidence(root, lab)
        # Recheck before first host mutation, under the same OPLA lock.
        audit(root, lab)
        evidence(root, lab)
        lifecycle_state = None
        if stop is None:
            lifecycle_state = lifecycle.load(str(root / lab))
            lifecycle.verify_lab_nft_policies(lifecycle_state)
        elif verify_policies is not None:
            verify_policies(root, lab)
        prune.write_journal(root, lab, 'planned', {'operation': 'active_creation_recovery', 'lab': lab})
        try:
            if stop is None:
                # The standard QMP stop never sends SIGKILL and refuses timeout.
                lifecycle.clean_stop(root / lab, lifecycle_state)
            else:
                stop(root, lab)
            # Never remove disks until proc/fd and all host resource probes confirm absent.
            evidence(root, lab)
            if offline is None:
                secure.remove_stale_sockets(root, lab)
                result = rollback.verify(root, lab)
                # rollback.execute takes its own lock; perform equivalent offline
                # directory deletion here while maintaining our exclusive lock.
                import shutil
                prune.write_journal(root, lab, 'offline_verified', {'operation':'active_creation_recovery'})
                rollback.verify(root, lab)
                shutil.rmtree(root / lab)
                (root / 'registry' / (lab + '.json')).unlink()
            else:
                result = offline(root, lab)
            prune.write_journal(root, lab, 'completed', {'operation':'active_creation_recovery'})
            return {'status': 'completed', 'lab': lab, 'offline': result}
        except Exception as exc:
            prune.write_journal(root, lab, 'failed', {'operation':'active_creation_recovery', 'error': str(exc)})
            raise
    finally:
        os.close(descriptor)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab', required=True)
    p.add_argument('--confirm', default='')
    p.add_argument('--root', default='/var/lib/opla')
    args = p.parse_args(argv)
    if os.geteuid() != 0:
        p.error('root required')
    try:
        print(json.dumps(locked_recover(Path(args.root), args.lab, args.confirm), indent=2))
        return 0
    except (RuntimeError, OSError, ValueError, TypeError, KeyError) as exc:
        print('BLOCKED:', exc, file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
