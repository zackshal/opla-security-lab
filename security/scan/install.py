#!/usr/bin/env python3
import argparse
import ipaddress
import os
from pathlib import Path
import subprocess

CODE = Path('/opt/opla-scan/detector.py')
UNIT = Path('/etc/systemd/system/opla-scan.service')
MARKER = Path('/etc/opla-scan/enabled')


def command(*args):
    return subprocess.run(args, check=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['start', 'status', 'off'])
    p.add_argument('--target', required=True)
    args = p.parse_args()
    target = str(ipaddress.IPv4Address(args.target))
    if os.geteuid() != 0:
        p.error('root required')
    if args.action == 'status':
        command('systemctl', 'status', 'opla-scan.service', '--no-pager', '-l')
        status = Path('/run/opla-scan/status.json')
        if status.exists():
            print(status.read_text())
        return
    if args.action == 'off':
        command('systemctl', 'disable', '--now', 'opla-scan.service')
        MARKER.unlink(missing_ok=True)
        return
    os.umask(0o077)
    for directory in [CODE.parent, MARKER.parent, Path('/run/opla-scan'),
                      Path('/var/lib/opla-scan'), Path('/var/log/opla-scan')]:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = Path(__file__).with_name('detector.py').read_bytes()
    unit = f'''[Unit]
Description=OPLA passive TCP distinct-port scan detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {CODE} --interface ens3 --target {target} --threshold 8 --window 60
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_RAW
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/run/opla-scan /var/lib/opla-scan /var/log/opla-scan
RuntimeDirectory=opla-scan
RuntimeDirectoryMode=0700
PrivateTmp=yes
RestrictAddressFamilies=AF_PACKET AF_UNIX

[Install]
WantedBy=multi-user.target
'''
    same = CODE.exists() and CODE.read_bytes() == data and UNIT.exists() and UNIT.read_text() == unit
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'opla-scan.service']).returncode == 0
    MARKER.write_text(target + '\n')
    if same and active:
        print('unchanged: passive detector active')
        return
    CODE.write_bytes(data)
    UNIT.write_text(unit)
    command('systemctl', 'daemon-reload')
    command('systemctl', 'enable', 'opla-scan.service')
    command('systemctl', 'restart', 'opla-scan.service')
    command('systemctl', 'is-active', '--quiet', 'opla-scan.service')
    print('Started passive detector; no blocking rules were installed')


if __name__ == '__main__':
    main()
