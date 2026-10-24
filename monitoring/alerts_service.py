#!/usr/bin/env python3
"""Install a user service without changing the Docker composition."""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['install', 'remove'])
    args = parser.parse_args()
    if os.getuid() == 0:
        raise SystemExit('Run as your normal user, without sudo')
    unit = Path.home() / '.config/systemd/user/opla-alerts.service'
    if args.action == 'remove':
        subprocess.run(['systemctl', '--user', 'disable', '--now', 'opla-alerts.service'], check=True)
        unit.unlink()
    else:
        worker = Path(__file__).resolve().with_name('alert_delivery.py')
        subprocess.run([sys.executable, str(worker), 'status'], check=True)
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(f'''[Unit]
Description=OPLA Warning+ alerts to Gmail and Proton through Tor
After=default.target

[Service]
Type=simple
ExecStart={quote(sys.executable)} {quote(worker)} run
Restart=on-failure
RestartSec=15
TimeoutStopSec=110
UMask=0077
NoNewPrivileges=yes

[Install]
WantedBy=default.target
''')
        os.chmod(unit, 0o600)
    subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
    if args.action == 'install':
        subprocess.run(['systemctl', '--user', 'enable', '--now', 'opla-alerts.service'], check=True)
        print('Started opla-alerts.service. Inspect queue status and journal; delivery is not yet confirmed.')


if __name__ == '__main__':
    main()
