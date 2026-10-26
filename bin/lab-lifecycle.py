#!/usr/bin/env python3
"""Safe stop/restart of a retained OPLA lab; never deletes VM disks."""
import argparse
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import time

from qmp import QMP
from state import load
import importlib.util
spec = importlib.util.spec_from_file_location('vm_disk', Path(__file__).with_name('vm-disk.py'))
vm_disk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm_disk)
VMS, resume = vm_disk.VMS, vm_disk.resume


def call(*args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True)


def active(name):
    return call('systemctl', 'is-active', '--quiet', name, check=False).returncode == 0


def installed(name):
    return call('systemctl', 'show', name, '-p', 'LoadState', '--value', check=False).stdout.strip() != 'not-found'


def interface(name):
    return call('ip', 'link', 'show', 'dev', name, check=False).returncode == 0


def remove_network(lab, state):
    """Remove only resources owned by this lab; retain all on-disk state."""
    labid, bridge = state['LAB_ID'], state['BRIDGE']
    table = 'opla_' + labid.replace('-', '_')
    dhcp = f'dhcp-{labid}.service'
    if active(dhcp):
        call('systemctl', 'stop', dhcp)
    # A stale DHCP unit is harmless. Avoid touching another lab's services.
    for _, (_, _, _, suffix) in VMS.items():
        tap = 'op' + bridge.removeprefix('br-op') + suffix
        if interface(tap):
            detail = call('ip', '-o', 'link', 'show', 'dev', tap).stdout
            if f'master {bridge}' not in detail:
                raise RuntimeError(f'{tap} не принадлежит {bridge}; очистка сети прервана')
            call('ip', 'link', 'delete', 'dev', tap)
    if interface(bridge):
        # Don't destroy a bridge shared with unexpected interfaces.
        attached = call('ip', '-o', 'link', 'show', 'master', bridge).stdout.strip()
        if attached:
            raise RuntimeError(f'У моста {bridge} остались интерфейсы; удаление отменено: {attached}')
        addresses = call('ip', '-o', '-4', 'addr', 'show', 'dev', bridge).stdout
        if state['GW'] + '/29' not in addresses:
            raise RuntimeError(f'IP моста {bridge} изменён; ручная проверка перед удалением')
        call('ip', 'link', 'delete', 'dev', bridge)
    if call('nft', 'list', 'table', 'inet', table, check=False).returncode == 0:
        call('nft', 'delete', 'table', 'inet', table)
    print('Сеть стенда остановлена: DHCP, TAP, bridge, nft; диски и state.env сохранены.')


def clean_stop(lab, state):
    labid = state['LAB_ID']
    running = [vm for vm in VMS if active(f'qemu-{labid}-{vm}.service')]
    if running:
        for vm in running:
            sock = lab / f'{vm}-qmp.sock'
            if not sock.is_socket():
                raise RuntimeError(f'Нет QMP-сокета {sock}; принудительную остановку не выполняем')
        for vm in running:
            try:
                with QMP(lab / f'{vm}-qmp.sock', timeout=6) as qmp:
                    qmp.call('system_powerdown')
            except (OSError, TimeoutError, RuntimeError) as exc:
                raise RuntimeError(f'Не удалось штатно выключить {vm}: {exc}') from exc
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            pending = [vm for vm in running if active(f'qemu-{labid}-{vm}.service')]
            if not pending:
                break
            time.sleep(2)
        else:
            raise RuntimeError('QEMU ещё работает: ' + ', '.join(pending) + '; сеть сохранена')
    remove_network(lab, state)
    print('Стенд полностью остановлен без удаления QCOW2.')


def preflight(lab, state):
    labid = state['LAB_ID']
    running = [vm for vm in VMS if active(f'qemu-{labid}-{vm}.service')]
    if running:
        raise RuntimeError('Обнаружены уже запущенные VM: ' + ', '.join(running) + '. Повторный запуск отменён.')
    for vm in VMS:
        for filename in ('disk.qcow2', 'seed.iso'):
            if not (lab / vm / filename).is_file():
                raise RuntimeError(f'Отсутствует {vm}/{filename}; запуск отменён')
    if not Path('/dev/kvm').exists():
        raise RuntimeError('/dev/kvm отсутствует')
    bridge = state['BRIDGE']
    if interface(bridge):
        # An existing bridge must have the expected subnet gateway.
        addresses = call('ip', '-o', '-4', 'addr', 'show', 'dev', bridge).stdout
        expected = state['GW'] + '/29'
        if expected not in addresses:
            raise RuntimeError(f'{bridge} уже существует, но не имеет {expected}; запуск отменён')
    else:
        # Avoid taking over a bridge name that is occupied by another lab.
        for entry in Path('/var/lib/opla').glob('lab-*/state.env'):
            if entry.parent == lab:
                continue
            try:
                other = load(str(entry.parent))
            except (OSError, ValueError, KeyError):
                continue
            if other['BRIDGE'] == bridge:
                raise RuntimeError(f'{bridge} записан за стендом {entry.parent.name}; отказ от запуска')
    # Prevalidate TAP ownership if they already exist.
    for vm, (_, _, _, suffix) in VMS.items():
        tap = 'op' + bridge.removeprefix('br-op') + suffix
        if interface(tap):
            master = call('ip', '-o', 'link', 'show', 'dev', tap).stdout
            if f'master {bridge}' not in master:
                raise RuntimeError(f'{tap} существует, но не подключён к {bridge}')


def prepare_network(lab, state):
    bridge, gateway, labid = state['BRIDGE'], state['GW'], state['LAB_ID']
    if not interface(bridge):
        call('ip', 'link', 'add', bridge, 'type', 'bridge')
        call('ip', 'addr', 'add', gateway + '/29', 'dev', bridge)
    call('ip', 'link', 'set', bridge, 'up')
    table = 'opla_' + labid.replace('-', '_')
    if call('nft', 'list', 'table', 'inet', table, check=False).returncode != 0:
        rules = f'''add table inet {table}
add chain inet {table} forward {{ type filter hook forward priority -20; policy accept; }}
add rule inet {table} forward iifname "{bridge}" oifname != "{bridge}" drop
add rule inet {table} forward oifname "{bridge}" iifname != "{bridge}" drop
add chain inet {table} input {{ type filter hook input priority -20; policy accept; }}
add rule inet {table} input iifname "{bridge}" ct state established,related accept
add rule inet {table} input iifname "{bridge}" udp dport 67 accept
add rule inet {table} input iifname "{bridge}" drop
'''
        subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
    for _, (_, _, _, suffix) in VMS.items():
        tap = 'op' + bridge.removeprefix('br-op') + suffix
        if not interface(tap):
            call('ip', 'tuntap', 'add', 'dev', tap, 'mode', 'tap')
        call('ip', 'link', 'set', tap, 'master', bridge)
        call('ip', 'link', 'set', tap, 'up')
    dhcp_unit = f'dhcp-{labid}.service'
    if not active(dhcp_unit):
        conf = lab / 'dnsmasq.conf'
        if not conf.is_file():
            raise RuntimeError(f'Отсутствует {conf}; DHCP не запущен')
        call('systemctl', 'reset-failed', dhcp_unit, check=False)
        call('systemd-run', '--quiet', '--collect', '--unit=dhcp-' + labid,
             'dnsmasq', '--keep-in-foreground', '--conf-file=' + str(conf))

    # Detect a missing local route before QEMU launch, to prevent a false success.
    route = call('ip', '-4', 'route', 'get', state['VICTIM_IP'], check=False)
    if route.returncode or ('dev ' + bridge) not in route.stdout:
        raise RuntimeError('Маршрут хоста до victim не использует ' + bridge +
                           ': ' + (route.stdout or route.stderr).strip() +
                           '. Проверьте ip route и конфликтующие сети.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'stop', 'status'))
    parser.add_argument('--lab', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Для операций с QEMU и TAP нужен sudo')
    state = load(args.lab)
    lab = Path(args.lab).resolve()
    with (lab / 'maintenance.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'status':
            bridge = state['BRIDGE']
            print(f'Stand: {lab.name}; bridge: {bridge} ({"UP" if interface(bridge) else "ABSENT"})')
            for vm in VMS:
                print(f'{vm}: {"RUNNING" if active('qemu-' + state['LAB_ID'] + '-' + vm + '.service') else "STOPPED"}')
            print(f'DHCP: {"RUNNING" if active('dhcp-' + state['LAB_ID'] + '.service') else "STOPPED"}')
        elif args.action == 'stop':
            clean_stop(lab, state)
        else:
            preflight(lab, state)
            prepare_network(lab, state)
            # resume() reuses existing QCOW2 images; it never creates new disks.
            resume(lab, state)
            print('Выполните make ready, затем проверьте XDP/IDS и запустите мониторинг.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as err:
        sys.exit(f'Ошибка управления стендом: {err}')
