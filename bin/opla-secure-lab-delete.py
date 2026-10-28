#!/usr/bin/env python3
"""OPLA v5.9 controlled lab deletion. Root required; fail closed.

Only a *registered* lab may be stopped and deleted. This does not manage
shared monitoring, Docker resources, external backups or shared base images.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import socket

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

prune = load('v59_prune', 'opla-offline-prune.py')
registry = prune.registry
lifecycle = load('v59_lifecycle', 'lab-lifecycle.py')

class Blocked(RuntimeError):
    pass

def command(args):
    p = prune.run_probe(args)
    if p.returncode != 0:
        raise Blocked('cannot inspect ' + ' '.join(args) + ': ' + p.stderr.strip())
    return p.stdout

def verify_tree_before_stop(root, lab):
    """Allow only known QMP/console sockets before shutdown."""
    directory=root/lab
    if directory.is_symlink() or not directory.is_dir() or directory.is_mount():
        raise Blocked('unsafe lab directory')
    allowed={f'{role}-{kind}.sock' for role in ('attacker','victim','client') for kind in ('qmp','console')}
    for base, dirs, files in os.walk(directory,topdown=True,followlinks=False):
        for name in dirs+files:
            path=Path(base)/name
            st=path.lstat()
            if stat.S_ISLNK(st.st_mode) or path.is_mount():
                raise Blocked('symlink or mount inside lab directory')
            if stat.S_ISSOCK(st.st_mode):
                if path.parent != directory or name not in allowed:
                    raise Blocked('unexpected socket in lab directory')
            elif not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise Blocked('unexpected device/FIFO inside lab directory')
            elif stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
                raise Blocked('hardlinked file inside lab directory')


def remove_stale_sockets(root,lab):
    """Remove QEMU socket pathnames only after all QEMU units/processes stop."""
    for proc in Path('/proc').glob('[0-9]*'):
        try: raw=(proc/'cmdline').read_bytes()
        except FileNotFoundError: continue
        except OSError: raise Blocked('cannot inspect process list before socket removal')
        if b'qemu-system' in raw and str(root/lab).encode() in raw:
            raise Blocked('QEMU still references lab disks; socket cleanup blocked')
    for role in ('attacker','victim','client'):
        for kind in ('qmp','console'):
            path=root/lab/f'{role}-{kind}.sock'
            try: st=path.lstat()
            except FileNotFoundError: continue
            if not stat.S_ISSOCK(st.st_mode):
                raise Blocked('unexpected non-socket at '+str(path))
            path.unlink()


def verify_pre_stop(root, lab):
    """Validate ownership evidence before any stop / network removal.

    Strictly refuse unexpected processes, units, table rules, bridge members,
    registry content and disk references. This is not a substitute for a
    kernel-enforced resource namespace or dedicated host.
    """
    root = prune.safe_root(root)
    if not registry.VALID.fullmatch(lab):
        raise Blocked('invalid lab ID')
    rd = root/'registry'
    rf = rd/(lab+'.json')
    if rd.is_symlink() or rf.is_symlink() or not rf.is_file():
        raise Blocked('missing or unsafe registry receipt')
    record = json.loads(rf.read_text())
    expected = registry.receipt(root, lab, 'ready')
    if (record.get('schema'), record.get('lab_id'), record.get('phase'), record.get('resources'), record.get('lab_dir')) != (1, lab, 'ready', expected['resources'], expected['lab_dir']):
        raise Blocked('registry identity/resources mismatch')
    # Verify all sibling records and resource uniqueness, including partially
    # created labs. Don't silently ignore other files in registry.
    owned = {(e['kind'],e['name']) for e in expected['resources']}
    for other in rd.iterdir():
        if other == rf: continue
        if other.is_symlink() or not other.is_file() or not registry.VALID.fullmatch(other.stem) or other.suffix != '.json':
            raise Blocked('unsafe sibling receipt')
        obj = json.loads(other.read_text())
        if obj.get('schema') != 1 or obj.get('lab_id') != other.stem:
            raise Blocked('bad sibling registry receipt')
        rec = registry.receipt(root,other.stem,obj.get('phase','creating'))
        if obj.get('resources') != rec['resources']:
            raise Blocked('sibling receipt mismatch')
        if owned & {(r['kind'],r['name']) for r in rec['resources']}:
            raise Blocked('resource collision with '+other.stem)
    verify_tree_before_stop(root,lab)
    # State content must also pass strict subnet and owner validation.
    state = lifecycle.load(str(root/lab))
    bridge = state['BRIDGE']
    vm_pids=set()
    for role in ('attacker','victim','client'):
        name=f'qemu-{lab}-{role}.service'
        if lifecycle.active(name):
            cmd=command(['systemctl','show',name,'--property=ExecStart','--value','--no-pager'])
            if ('qemu-system' not in cmd or str(root/lab/role/'disk.qcow2') not in cmd):
                raise Blocked(name+' command does not match lab disk')
            pid_info=command(['systemctl','show',name,'--property=MainPID','--value','--no-pager']).strip()
            if not pid_info.isdigit() or int(pid_info)<=0:
                raise Blocked('QEMU unit has no tracked PID')
            vm_pids.add(pid_info)
    dhcp=f'dhcp-{lab}.service'
    if lifecycle.active(dhcp):
        cmd=command(['systemctl','show',dhcp,'--property=ExecStart','--value','--no-pager'])
        if ('dnsmasq' not in cmd or str(root/lab/'dnsmasq.conf') not in cmd):
            raise Blocked('DHCP unit ExecStart differs from lab configuration')
    if lifecycle.interface(bridge):
        addr=command(['ip','-o','-4','addr','show','dev',bridge])
        if state['GW']+'/29' not in addr:
            raise Blocked('bridge address mismatch')
        members=command(['ip','-o','link','show','master',bridge])
        expected_taps={'op'+bridge.removeprefix('br-op')+x for x in 'avc'}
        for line in members.splitlines():
            parts=line.split(':',2)
            if len(parts)<2 or parts[1].strip().split('@')[0] not in expected_taps:
                raise Blocked('unknown bridge member')
    for suffix in 'avc':
        tap='op'+bridge.removeprefix('br-op')+suffix
        if lifecycle.interface(tap):
            detail=command(['ip','-o','link','show','dev',tap])
            if 'master '+bridge not in detail:
                raise Blocked('TAP master mismatch: '+tap)
    table='opla_'+lab.replace('-','_')
    check=prune.run_probe(['nft','list','table','inet',table])
    if check.returncode == 0:
        output=check.stdout
        # Reject unrecognized chains/rules. Any custom rules require manual
        # examination rather than wholesale table deletion.
        canonical=['table inet '+table, 'chain forward', 'chain input',
                   'type filter hook forward priority -20; policy accept;',
                   'type filter hook input priority -20; policy accept;',
                   'iifname "'+bridge+'" oifname != "'+bridge+'" drop',
                   'oifname "'+bridge+'" iifname != "'+bridge+'" drop',
                   'iifname "'+bridge+'" ct state established,related accept',
                   'iifname "'+bridge+'" udp dport 67 accept',
                   'iifname "'+bridge+'" drop']
        lines=[x.strip() for x in output.splitlines() if x.strip() and not x.strip().startswith('#')]
        found=set()
        for line in lines:
            if line in ('{','}'):
                continue
            matched=[expected for expected in canonical if line == expected or
                     (line.startswith(expected) and line[len(expected):].strip() in ('{','}'))]
            if len(matched)!=1:
                raise Blocked('unrecognized nft rule; manual inspection required: '+line)
            found.add(matched[0])
        if found != set(canonical):
            raise Blocked('nft table policy differs from expected OPLA rules')
    elif check.returncode != 1 or not re.search('no such file|does not exist',check.stderr,re.I):
        raise Blocked('cannot safely inspect nft table')
    # Detect unrelated processes referencing the lab (not just QEMU).
    target=str(root/lab).encode()
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            raw=(proc/'cmdline').read_bytes()
        except FileNotFoundError:
            continue
        except OSError:
            raise Blocked('cannot inspect process list')
        if target in raw:
            if b'qemu-system' not in raw:
                raise Blocked('non-QEMU process references the lab: '+proc.name)
            if proc.name not in vm_pids:
                raise Blocked('untracked QEMU references the lab: '+proc.name)
    return state

def run(root,lab,confirm):
    root=prune.safe_root(root)
    if confirm != 'DELETE-LAB:'+lab:
        raise Blocked('confirmation must be DELETE-LAB:'+lab)
    lf=root/'.opla-prune.lock'
    fd=os.open(lf,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Blocked('unsafe global lifecycle lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state=verify_pre_stop(root,lab)
        prune.write_journal(root,lab,'planned',{'mode':'online','lab':lab})
        try:
            # QMP graceful shutdown. No SIGKILL; abort on timeout.
            lifecycle.clean_stop(root/lab,state)
            prune.write_journal(root,lab,'deprovisioned',{'mode':'offline'})
            remove_stale_sockets(root,lab)
            # Offline executor rechecks service state, /proc and symlinks.
            result=prune.execute(root,lab,'DELETE-OFFLINE:'+lab,lock_held=True)
        except Exception as exc:
            prune.write_journal(root,lab,'failed',str(exc))
            raise
        return result
    finally:
        os.close(fd)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',default='/var/lib/opla')
    p.add_argument('--plan',action='store_true')
    p.add_argument('--lab',required=True)
    p.add_argument('--confirm',default='')
    args=p.parse_args(argv)
    if os.geteuid()!=0:
        p.error('requires root')
    try:
        if args.plan:
            report=verify_pre_stop(Path(args.root),args.lab)
            print(json.dumps({'lab':args.lab,'status':'preflight_only','safe_for_deletion':False,'bridge':report['BRIDGE']},indent=2))
        else:
            print(json.dumps(run(Path(args.root),args.lab,args.confirm),indent=2))
    except (OSError,ValueError,RuntimeError,KeyError,TypeError) as exc:
        print('BLOCKED:',exc,file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':
    sys.exit(main())
