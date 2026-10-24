#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import yaml

ROOT = Path('/etc/opla-suricata')
LOG = Path('/var/log/opla-suricata')
UNIT = Path('/etc/systemd/system/opla-suricata.service')
TABLE = 'opla_ips'
INTERFACE = 'ens3'

def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)

def queue_rules():
    return '''table inet opla_ips {
 chain input { type filter hook input priority 10; policy accept;
  iifname "__INTERFACE__" tcp dport 80 counter queue num 42
 }
 chain output { type filter hook output priority 10; policy accept;
  oifname "__INTERFACE__" tcp sport 80 counter queue num 42
 }
}
'''.replace('__INTERFACE__', INTERFACE)

def table_exists():
    return subprocess.run(['nft', 'list', 'table', 'inet', TABLE], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0

def remove_queue():
    if table_exists():
        run('nft', 'delete', 'table', 'inet', TABLE)

def config(mode, subnet, et_open):
    import ipaddress
    network = ipaddress.ip_network(subnet, strict=True)
    if network.version != 4:
        raise ValueError('IPv4 HOME_NET required')
    data = yaml.safe_load(Path('/etc/suricata/suricata.yaml').read_text())
    data.setdefault('vars', {}).setdefault('address-groups', {})['HOME_NET'] = str(network)
    data['vars']['address-groups']['EXTERNAL_NET'] = 'any'
    data['default-log-dir'] = str(LOG)
    data['default-rule-path'] = str(ROOT)
    data['rule-files'] = ['opla.rules'] + (['ips.rules'] if mode == 'ips' else [])
    if et_open:
        rules = Path('/var/lib/suricata/rules/suricata.rules')
        if not rules.is_file():
            raise ValueError('ET rules missing; prepare them before isolating the guest')
        data['rule-files'].append(str(rules))
    data['af-packet'] = [{'interface': INTERFACE, 'threads': 1, 'cluster-id': 91,
                          'cluster-type': 'cluster_flow', 'defrag': True,
                          'use-mmap': True, 'tpacket-v3': True}]
    data.setdefault('stream', {})['inline'] = mode == 'ips'
    data['outputs'] = [{'eve-log': {'enabled': True, 'filetype': 'regular',
                                  'filename': 'eve.json', 'types': ['alert', 'drop', 'stats']}}]
    data['stats'] = {'enabled': True, 'interval': 10}
    data['flow'] = dict(data.get('flow', {}), memcap='32mb')
    data.setdefault('stream', {})['memcap'] = '32mb'
    data['stream'].setdefault('reassembly', {})['memcap'] = '64mb'
    return data

def apply(mode, subnet, et_open=False):
    ROOT.mkdir(mode=0o750, exist_ok=True)
    LOG.mkdir(mode=0o750, exist_ok=True)
    import tempfile
    with tempfile.TemporaryDirectory(prefix='rules-', dir=ROOT) as temporary:
        stage_path = Path(temporary)
        rules_changed = False
        old_rules = {}
        for name in ['opla.rules', 'ips.rules']:
            content = (Path(__file__).parent / name).read_bytes()
            old_rules[name] = (ROOT/name).read_bytes() if (ROOT/name).exists() else None
            rules_changed |= old_rules[name] != content
            (stage_path/name).write_bytes(content)
        candidate = ROOT / 'suricata.next.yaml'
        settings = config(mode, subnet, et_open)
        settings['default-rule-path'] = str(stage_path)
        candidate.write_text(yaml.safe_dump(settings, sort_keys=False, explicit_start=True, version=(1, 1)))
        run('suricata', '-T', '-c', str(candidate))
        settings['default-rule-path'] = str(ROOT)
        candidate.write_text(yaml.safe_dump(settings, sort_keys=False, explicit_start=True, version=(1, 1)))
        if mode == 'ips':
            build = subprocess.check_output(['suricata', '--build-info'], text=True)
            if 'NFQueue support:                        yes' not in build and not any(
                    'NFQueue support' in line and 'yes' in line for line in build.splitlines()):
                raise RuntimeError('Suricata lacks NFQueue support')
        active_config = ROOT / 'suricata.yaml'
        import hashlib
        et_digest = hashlib.sha256(Path('/var/lib/suricata/rules/suricata.rules').read_bytes()).hexdigest() if et_open else None
        desired = {'mode': mode, 'home_net': subnet, 'interface': INTERFACE, 'et_open': et_open, 'et_sha256': et_digest,
                   'runtime_sha256': hashlib.sha256((Path(__file__).parent/'runtime.py').read_bytes()).hexdigest(),
                   'manager_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        current_mode = json.loads((ROOT/'mode.json').read_text()) if (ROOT/'mode.json').exists() else {}
        running = subprocess.run(['systemctl', 'is-active', '--quiet', 'opla-suricata.service'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if (not rules_changed and current_mode == desired and active_config.exists()
                and active_config.read_bytes() == candidate.read_bytes() and running
                and table_exists() == (mode == 'ips')):
            candidate.unlink()
            print('unchanged')
            return
        before = active_config.read_bytes() if active_config.exists() else None
        old_unit = UNIT.read_bytes() if UNIT.exists() else None
        for name in old_rules:
            (ROOT/name).write_bytes((stage_path/name).read_bytes())
        candidate.replace(active_config)
        capture = '-q 42' if mode == 'ips' else '--af-packet=' + INTERFACE
        (ROOT/'runtime.py').write_bytes((Path(__file__).parent/'runtime.py').read_bytes())
        UNIT.write_text(f'''[Unit]
    Description=OPLA Suricata {mode}
    After=network.target
    [Service]
    Type=simple
    ExecStart=/usr/bin/suricata -c {active_config} {capture} --runmode workers
    ExecStartPost=/usr/bin/python3 {ROOT}/runtime.py {mode} {INTERFACE}
    Restart=on-failure
    RestartSec=2
    UMask=0027
    NoNewPrivileges=yes
    ProtectHome=yes
    ProtectSystem=strict
    ReadWritePaths={LOG} /run
    PrivateTmp=yes
    [Install]
    WantedBy=multi-user.target
    ''')
        try:
            run('systemctl', 'daemon-reload')
            run('systemctl', 'restart', 'opla-suricata.service')
            run('systemctl', 'is-active', '--quiet', 'opla-suricata.service')
            (ROOT / 'mode.json').write_text(json.dumps(desired) + '\n')
            run('systemctl', 'enable', 'opla-suricata.service')
        except Exception:
            for name, content in old_rules.items():
                if content is None:
                    (ROOT/name).unlink(missing_ok=True)
                else:
                    (ROOT/name).write_bytes(content)
            if before is not None and old_unit is not None:
                active_config.write_bytes(before)
                UNIT.write_bytes(old_unit)
                subprocess.run(['systemctl', 'daemon-reload'])
                subprocess.run(['systemctl', 'restart', 'opla-suricata.service'])
            else:
                remove_queue()
                subprocess.run(['systemctl', 'stop', 'opla-suricata.service'])
            raise
        print('changed: Suricata', mode, 'active; IPS HTTP path fails closed if the engine stops')

def main():
    global INTERFACE
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['ids', 'ips', 'off', 'status'])
    p.add_argument('--subnet')
    p.add_argument('--interface', default='ens3')
    p.add_argument('--et-open', action='store_true')
    a = p.parse_args()
    import re
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', a.interface):
        p.error('Invalid interface')
    INTERFACE = a.interface
    if os.geteuid() != 0:
        p.error('Run as root inside victim')
    if a.mode == 'status':
        subprocess.run(['systemctl', 'status', 'opla-suricata.service', '--no-pager'])
        subprocess.run(['nft', 'list', 'table', 'inet', TABLE])
    elif a.mode == 'off':
        remove_queue()
        subprocess.run(['systemctl', 'disable', '--now', 'opla-suricata.service'], check=False)
        (ROOT / 'mode.json').unlink(missing_ok=True)
    elif a.subnet:
        apply(a.mode, a.subnet, a.et_open)
    else:
        p.error('--subnet required')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
