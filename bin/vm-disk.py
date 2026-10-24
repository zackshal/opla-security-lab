#!/usr/bin/env python3
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from state import load

VMS = {'attacker': (1024, 1, '02', 'a'), 'victim': (2048, 2, '03', 'v'),
       'client': (512, 1, '04', 'c')}

def run(*args):
    return subprocess.check_output(args, text=True).strip()

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def offline(data):
    for vm in VMS:
        unit = f'qemu-{data["LAB_ID"]}-{vm}.service'
        if run('systemctl', 'show', unit, '-p', 'MainPID', '--value') not in ('', '0'):
            raise RuntimeError('Shut down all guests cleanly first; do not use make down')

def validate_image(path):
    info = json.loads(run('qemu-img', 'info', '--output=json', str(path)))
    if info.get('format') != 'qcow2' or info.get('backing-filename'):
        raise RuntimeError('Expected a standalone qcow2 without a backing file')
    subprocess.run(['qemu-img', 'check', '-f', 'qcow2', str(path)], check=True)

def backup(lab, destination):
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {'version': 1, 'lab': lab.name,
                'created': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'images': {}}
    for vm in VMS:
        target = destination / (vm + '.qcow2')
        subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2',
                        str(lab / vm / 'disk.qcow2'), str(target)], check=True)
        validate_image(target)
        manifest['images'][vm] = {'file': target.name, 'sha256': sha(target)}
        (destination / (vm + '-seed.iso')).write_bytes((lab / vm / 'seed.iso').read_bytes())
    (destination / 'state.env').write_bytes((lab / 'state.env').read_bytes())
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(destination)

def restore(lab, source, vm):
    manifest = json.loads((source / 'manifest.json').read_text())
    record = manifest['images'][vm]
    image = source / (vm + '.qcow2')
    if record['file'] != image.name or sha(image) != record['sha256']:
        raise RuntimeError('Backup filename/checksum mismatch')
    validate_image(image)
    target = lab / vm / 'disk.qcow2'
    staging = target.with_name('disk.restore-part.qcow2')
    if staging.exists():
        raise RuntimeError('Previous incomplete restore exists: inspect it first')
    subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2',
                    str(image), str(staging)], check=True)
    validate_image(staging)
    old = target.with_name('disk.before-restore-' + datetime.datetime.now().strftime('%Y%m%d%H%M%S%f') + '.qcow2')
    target.rename(old)
    try:
        staging.rename(target)
    except OSError:
        old.rename(target)
        raise
    print('Restored disk only; old disk retained at', old)

def resume(lab, data):
    for vm, (memory, cpus, mac, suffix) in VMS.items():
        tap = 'op' + data['BRIDGE'].removeprefix('br-op') + suffix
        run('ip', 'link', 'show', 'dev', tap)
        seed = lab / vm / 'seed.iso'
        if not seed.exists():
            raise RuntimeError('Missing seed ISO; resume requires an existing retained lab')
        for kind in ['console', 'qmp']:
            socket = lab / (vm + '-' + kind + '.sock')
            if socket.exists():
                if not socket.is_socket():
                    raise RuntimeError('Unexpected non-socket at ' + str(socket))
                socket.unlink()
        command = ['systemd-run', '--quiet', '--collect', '--property=UMask=0077',
                   '--unit=qemu-' + data['LAB_ID'] + '-' + vm,
                   'qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-m', str(memory),
                   '-smp', str(cpus), '-drive', f'file={lab / vm / "disk.qcow2"},if=virtio',
                   '-drive', f'file={seed},media=cdrom',
                   '-netdev', f'tap,id=n0,ifname={tap},script=no,downscript=no',
                   '-device', 'virtio-net-pci,netdev=n0,mac=52:54:00:00:00:' + mac,
                   '-chardev', f'socket,id=c0,path={lab}/{vm}-console.sock,server=on,wait=off',
                   '-serial', 'chardev:c0', '-display', 'none', '-monitor', 'none',
                   '-qmp', f'unix:{lab}/{vm}-qmp.sock,server=on,wait=off', '-no-reboot']
        subprocess.run(command, check=True)
        import time
        console = lab / (vm + '-console.sock')
        for _ in range(50):
            if console.exists():
                os.chown(console, (lab/'known_hosts').stat().st_uid, -1)
                break
            time.sleep(.1)
        else:
            raise RuntimeError('Console did not appear for ' + vm)
    print('Guests launched; make ready, verify XDP/HTTP/IDS and restart collector')

def main():
    p = argparse.ArgumentParser(description='Offline disk backup, restore and resume of a retained lab')
    p.add_argument('action', choices=['backup', 'restore', 'resume'])
    p.add_argument('--lab', required=True)
    p.add_argument('--directory', type=Path)
    p.add_argument('--vm', choices=list(VMS), default='victim')
    p.add_argument('--confirm-restore', action='store_true')
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error('Run with sudo')
    os.umask(0o077)
    data = load(a.lab)
    lab = Path(a.lab).resolve()
    with (lab / 'maintenance.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        offline(data)
        if a.action == 'resume':
            resume(lab, data)
        elif a.directory is None:
            p.error('--directory required')
        elif a.action == 'restore':
            if not a.confirm_restore:
                p.error('--confirm-restore required')
            restore(lab, a.directory.resolve(), a.vm)
        else:
            backup(lab, a.directory.resolve())

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
