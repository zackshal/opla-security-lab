#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parent))
from nft_policy import TABLE, delete_owned_table, exclusive_lock, table_status

ROOT = Path('/etc/opla-suricata')
LOG = Path('/var/log/opla-suricata')
UNIT = Path('/etc/systemd/system/opla-suricata.service')
INTERFACE = 'ens3'
MANAGER_LOCK_PATH = Path('/run/lock/opla-suricata-manager.lock')
UNIT_MARKER = '# OPLA-SURICATA-MANAGED-V1'

def validate_unit_parent_chain(path=UNIT):
    """Require systemd unit ancestors to be root-owned protected directories."""
    cursor = Path(path).absolute().parent
    while True:
        try:
            info = cursor.lstat()
        except OSError as error:
            raise RuntimeError('Suricata unit directory is unavailable or untrusted') from error
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise RuntimeError('Suricata unit directory is not root-owned and protected')
        if cursor == cursor.parent:
            break
        cursor = cursor.parent


def validate_unit_metadata(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Suricata unit is not a single-link regular file')
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError('Suricata unit is not root-owned and protected')


def owned_unit_bytes():
    validate_unit_parent_chain(UNIT)
    try:
        info = UNIT.lstat()
    except FileNotFoundError:
        return None
    validate_unit_metadata(info)
    content = UNIT.read_bytes()
    if not content.startswith((UNIT_MARKER + '\n').encode()):
        raise RuntimeError('Suricata unit is unmarked; manual review required')
    return content

def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)

def table_exists():
    status = table_status()
    if status == 'FOREIGN':
        raise RuntimeError('nft table inet opla_ips is unmarked; manual review required')
    return status == 'OWNED'

def remove_queue():
    delete_owned_table()

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

def write_mode_receipt(path, raw):
    """Atomically persist mode state without following or overwriting a temp path."""
    import tempfile
    fd, temporary = tempfile.mkstemp(prefix='.mode-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

def _apply(mode, subnet, et_open=False):
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
        mode_path = ROOT / 'mode.json'
        try:
            mode_info = mode_path.lstat()
        except FileNotFoundError:
            old_mode_raw = None
            current_mode = {}
        else:
            if not mode_path.is_file() or mode_path.is_symlink() or mode_info.st_nlink != 1:
                raise RuntimeError('Suricata mode receipt is not a single-link regular file')
            old_mode_raw = mode_path.read_bytes()
            current_mode = json.loads(old_mode_raw)
        old_unit = owned_unit_bytes()
        unit_probe = subprocess.run(['systemctl', 'is-enabled', 'opla-suricata.service'],
                                    capture_output=True, text=True)
        unit_state = unit_probe.stdout.strip()
        if old_unit is None:
            if (unit_probe.returncode == 0 or unit_state not in ('', 'not-found')
                    or old_mode_raw is not None):
                raise RuntimeError('Suricata unit/receipt state is inconsistent; manual reconciliation required')
            old_enabled = False
        else:
            if (unit_state not in ('enabled', 'disabled')
                    or (unit_state == 'enabled' and unit_probe.returncode != 0)
                    or (unit_state == 'disabled' and unit_probe.returncode == 0)):
                raise RuntimeError('Suricata unit enablement is unknown; manual reconciliation required')
            old_enabled = unit_state == 'enabled'
        running = subprocess.run(['systemctl', 'is-active', '--quiet', 'opla-suricata.service'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if running and (old_mode_raw is None or old_unit is None):
            raise RuntimeError('Suricata is active without a mode receipt; manual reconciliation required')
        if (not rules_changed and current_mode == desired and active_config.exists()
                and active_config.read_bytes() == candidate.read_bytes() and running
                and table_exists() == (mode == 'ips')):
            candidate.unlink()
            print('unchanged')
            return
        before = active_config.read_bytes() if active_config.exists() else None
        if (before is None) != (old_unit is None):
            raise RuntimeError('Suricata config and unit presence disagree; manual reconciliation required')
        old_helpers = {}
        for helper_name in ('runtime.py', 'nft_policy.py'):
            helper = ROOT / helper_name
            old_helpers[helper_name] = helper.read_bytes() if helper.exists() else None
        capture = '-q 42' if mode == 'ips' else '--af-packet=' + INTERFACE
        service_mutation_started = False
        try:
            for name in old_rules:
                (ROOT/name).write_bytes((stage_path/name).read_bytes())
            candidate.replace(active_config)
            (ROOT/'runtime.py').write_bytes((Path(__file__).parent/'runtime.py').read_bytes())
            (ROOT/'nft_policy.py').write_bytes((Path(__file__).parent/'nft_policy.py').read_bytes())
            UNIT.write_text(f'''{UNIT_MARKER}
    [Unit]
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
            service_mutation_started = True
            run('systemctl', 'daemon-reload')
            run('systemctl', 'restart', 'opla-suricata.service')
            run('systemctl', 'is-active', '--quiet', 'opla-suricata.service')
            run('systemctl', 'enable', 'opla-suricata.service')
            write_mode_receipt(mode_path, (json.dumps(desired) + '\n').encode())
        except Exception as operation_error:
            try:
                if old_mode_raw is None:
                    mode_path.unlink(missing_ok=True)
                else:
                    write_mode_receipt(mode_path, old_mode_raw)
                for name, content in old_rules.items():
                    if content is None:
                        (ROOT/name).unlink(missing_ok=True)
                    else:
                        (ROOT/name).write_bytes(content)
                if service_mutation_started and old_unit is None:
                    subprocess.run(['systemctl', 'disable', '--now', 'opla-suricata.service'], check=True)
                if old_unit is not None:
                    active_config.write_bytes(before)
                    UNIT.write_bytes(old_unit)
                else:
                    active_config.unlink(missing_ok=True)
                    UNIT.unlink(missing_ok=True)
                for helper_name, content in old_helpers.items():
                    helper = ROOT / helper_name
                    if content is None:
                        helper.unlink(missing_ok=True)
                    else:
                        helper.write_bytes(content)
                if service_mutation_started:
                    if old_unit is not None:
                        subprocess.run(['systemctl', 'daemon-reload'], check=True)
                        action = 'enable' if old_enabled else 'disable'
                        subprocess.run(['systemctl', action, 'opla-suricata.service'], check=True)
                        action = 'restart' if running else 'stop'
                        subprocess.run(['systemctl', action, 'opla-suricata.service'], check=True)
                    else:
                        remove_queue()
                        subprocess.run(['systemctl', 'daemon-reload'], check=True)
            except Exception as rollback_error:
                raise RuntimeError('Suricata rollback incomplete; manual reconciliation required') from rollback_error
            raise
        print('changed: Suricata', mode, 'active; IPS HTTP path fails closed if the engine stops')

def apply(mode, subnet, et_open=False):
    with exclusive_lock(MANAGER_LOCK_PATH):
        return _apply(mode, subnet, et_open)

def turn_off():
    """Stop the service before removing its queue and saved mode."""
    with exclusive_lock(MANAGER_LOCK_PATH):
        if owned_unit_bytes() is None:
            raise RuntimeError('managed Suricata unit is missing; manual reconciliation required')
        run('systemctl', 'disable', '--now', 'opla-suricata.service')
        active = subprocess.run(['systemctl', 'is-active', 'opla-suricata.service'],
                                capture_output=True, text=True)
        if active.stdout.strip() != 'inactive':
            raise RuntimeError('Suricata service did not reach inactive state')
        enabled = subprocess.run(['systemctl', 'is-enabled', 'opla-suricata.service'],
                                 capture_output=True, text=True)
        if enabled.stdout.strip() != 'disabled':
            raise RuntimeError('Suricata service did not reach disabled state')
        remove_queue()
        (ROOT / 'mode.json').unlink(missing_ok=True)

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
        turn_off()
    elif a.subnet:
        apply(a.mode, a.subnet, a.et_open)
    else:
        p.error('--subnet required')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
