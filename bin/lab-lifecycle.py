#!/usr/bin/env python3
"""Safe stop/restart of a retained OPLA lab; never deletes VM disks."""
import argparse
from contextlib import ExitStack
import fcntl
import math
import os
import re
import signal
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


DEFAULT_COMMAND_TIMEOUT = 30.0
COMMAND_TERMINATION_GRACE = 2.0


def _validate_timeout(timeout):
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("lifecycle command timeout must be finite and positive")


def _run_owned(args, *, check, timeout, input, **_kwargs):
    """Run one lifecycle child in an owned process group and reap on timeout."""
    process = subprocess.Popen(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if input is not None else None,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(input=input, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as timeout_error:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            stdout, stderr = process.communicate(timeout=COMMAND_TERMINATION_GRACE)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                process.communicate()
            except OSError:
                pass
        except OSError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                process.communicate()
            except OSError:
                pass
        raise timeout_error
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if check and result.returncode:
        raise subprocess.CalledProcessError(
            result.returncode, args, output=result.stdout, stderr=result.stderr
        )
    return result


def call(*args, check=True, timeout=DEFAULT_COMMAND_TIMEOUT, input=None, runner=None):
    _validate_timeout(timeout)
    dispatch = subprocess.run if runner is None else runner
    if runner is None:
        dispatch = _run_owned
    return dispatch(
        args,
        check=check,
        text=True,
        capture_output=True,
        input=input,
        timeout=timeout,
    )


def active(name):
    return call('systemctl', 'is-active', '--quiet', name, check=False).returncode == 0


def installed(name):
    return call('systemctl', 'show', name, '-p', 'LoadState', '--value', check=False).stdout.strip() != 'not-found'


def interface(name):
    return call('ip', 'link', 'show', 'dev', name, check=False).returncode == 0


def verify_nft_before_network_cleanup(table, bridge, *, management=False):
    """Fail closed on unexpected NFT rules before mutating DHCP/TAP/bridge.

    Missing table is allowed; unexpected permissions/output/extra rules are not.
    This is a defense in depth for direct lab-stop calls, not ownership proof.
    """
    probe = call('nft', 'list', 'table', 'inet', table, check=False)
    if probe.returncode:
        if probe.returncode == 1 and re.search(r'no such file|does not exist', probe.stderr, re.I):
            return False
        raise RuntimeError(f'Cannot safely inspect nftables table {table}: {probe.stderr.strip()}')
    expected = {
        f'table inet {table}',
        'chain forward',
        'type filter hook forward priority -20; policy accept;',
        f'iifname "{bridge}" oifname != "{bridge}" drop',
        f'oifname "{bridge}" iifname != "{bridge}" drop',
    }
    if management:
        expected.update({
            'chain input',
            'type filter hook input priority -19; policy accept;',
            f'iifname "{bridge}" drop',
        })
        expected = {line.replace('priority -20;', 'priority -19;') for line in expected}
    else:
        expected.update({
            'chain input',
            'type filter hook input priority -20; policy accept;',
            f'iifname "{bridge}" ct state established,related accept',
            f'iifname "{bridge}" udp dport 67 accept',
            f'iifname "{bridge}" drop',
        })
    actual = []
    for line in probe.stdout.splitlines():
        line = line.strip()
        if not line or line in ('{', '}'):
            continue
        # Strip only structural opening brace. Unknown inline comments/rules block.
        if line.endswith(' {'):
            line = line[:-2].rstrip()
        actual.append(line)
    if len(actual) != len(expected) or set(actual) != expected:
        raise RuntimeError(f'nftables table {table} differs from expected OPLA policy; manual review required')
    return True


def remove_network(lab, state):
    """Remove only resources owned by this lab; retain all on-disk state."""
    if 'MGMT_BRIDGE' not in state:
        raise RuntimeError('dual-NIC laboratory state required; manual migration required')
    labid, bridge, mgmt_bridge = state['LAB_ID'], state['BRIDGE'], state['MGMT_BRIDGE']
    table = 'opla_' + labid.replace('-', '_')
    mgmt_table = 'opla_mgmt_' + labid.replace('-', '_')
    dhcp = f'dhcp-{labid}.service'
    nft_present = verify_nft_before_network_cleanup(table, bridge)
    mgmt_nft_present = verify_nft_before_network_cleanup(mgmt_table, mgmt_bridge, management=True)
    if active(dhcp):
        call('systemctl', 'stop', dhcp)
    # A stale DHCP unit is harmless. Avoid touching another lab's services.
    for _, (_, _, _, suffix, _, mgmt_suffix) in VMS.items():
        tap = 'op' + bridge.removeprefix('br-op') + suffix
        if interface(tap):
            detail = call('ip', '-o', 'link', 'show', 'dev', tap).stdout
            if f'master {bridge}' not in detail:
                raise RuntimeError(f'{tap} не принадлежит {bridge}; очистка сети прервана')
            call('ip', 'link', 'delete', 'dev', tap)
        mgmt_tap = 'op' + mgmt_bridge.removeprefix('br-op') + mgmt_suffix
        if interface(mgmt_tap):
            detail = call('ip', '-o', 'link', 'show', 'dev', mgmt_tap).stdout
            if f'master {mgmt_bridge}' not in detail:
                raise RuntimeError(f'{mgmt_tap} не принадлежит {mgmt_bridge}; очистка сети прервана')
            call('ip', 'link', 'delete', 'dev', mgmt_tap)
    for current_bridge, gateway in ((bridge, state['GW']), (mgmt_bridge, state['MGMT_GW'])):
      if interface(current_bridge):
        # Don't destroy a bridge shared with unexpected interfaces.
        attached = call('ip', '-o', 'link', 'show', 'master', current_bridge).stdout.strip()
        if attached:
            raise RuntimeError(f'У моста {current_bridge} остались интерфейсы; удаление отменено: {attached}')
        addresses = call('ip', '-o', '-4', 'addr', 'show', 'dev', current_bridge).stdout
        if gateway + '/29' not in addresses:
            raise RuntimeError(f'IP моста {current_bridge} изменён; ручная проверка перед удалением')
        call('ip', 'link', 'delete', 'dev', current_bridge)
    if nft_present:
        # Recheck immediately before deletion; reject policy changes during cleanup.
        if not verify_nft_before_network_cleanup(table, bridge):
            raise RuntimeError('nft table disappeared during cleanup; manual review required')
        call('nft', 'delete', 'table', 'inet', table)
    if mgmt_nft_present:
        if not verify_nft_before_network_cleanup(mgmt_table, mgmt_bridge, management=True):
            raise RuntimeError('management nft table disappeared during cleanup; manual review required')
        call('nft', 'delete', 'table', 'inet', mgmt_table)
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
    if 'MGMT_BRIDGE' not in state:
        raise RuntimeError('dual-NIC laboratory state required; refusing single-NIC resume')
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
    for bridge, gateway in ((state['BRIDGE'], state['GW']), (state['MGMT_BRIDGE'], state['MGMT_GW'])):
        if interface(bridge):
            addresses = call('ip', '-o', '-4', 'addr', 'show', 'dev', bridge).stdout
            expected = gateway + '/29'
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
                if bridge in (other.get('BRIDGE'), other.get('MGMT_BRIDGE')):
                    raise RuntimeError(f'{bridge} записан за стендом {entry.parent.name}; отказ от запуска')
    # Prevalidate TAP ownership if they already exist.
    for vm, (_, _, _, suffix, _, mgmt_suffix) in VMS.items():
        for bridge, tap_suffix in ((state['BRIDGE'], suffix), (state['MGMT_BRIDGE'], mgmt_suffix)):
            tap = 'op' + bridge.removeprefix('br-op') + tap_suffix
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
        call('nft', '-f', '-', input=rules)
    mgmt_bridge = state['MGMT_BRIDGE']
    mgmt_table = 'opla_mgmt_' + labid.replace('-', '_')
    if not interface(mgmt_bridge):
        call('ip', 'link', 'add', mgmt_bridge, 'type', 'bridge')
        call('ip', 'addr', 'add', state['MGMT_GW'] + '/29', 'dev', mgmt_bridge)
    call('ip', 'link', 'set', mgmt_bridge, 'up')
    if call('nft', 'list', 'table', 'inet', mgmt_table, check=False).returncode != 0:
        rules = f'''add table inet {mgmt_table}
add chain inet {mgmt_table} forward {{ type filter hook forward priority -19; policy accept; }}
add rule inet {mgmt_table} forward iifname "{mgmt_bridge}" oifname != "{mgmt_bridge}" drop
add rule inet {mgmt_table} forward oifname "{mgmt_bridge}" iifname != "{mgmt_bridge}" drop
add chain inet {mgmt_table} input {{ type filter hook input priority -19; policy accept; }}
add rule inet {mgmt_table} input iifname "{mgmt_bridge}" drop
'''
        call('nft', '-f', '-', input=rules)
    for _, (_, _, _, suffix, _, mgmt_suffix) in VMS.items():
        tap = 'op' + bridge.removeprefix('br-op') + suffix
        if not interface(tap):
            call('ip', 'tuntap', 'add', 'dev', tap, 'mode', 'tap')
        call('ip', 'link', 'set', tap, 'master', bridge)
        call('ip', 'link', 'set', tap, 'up')
        mgmt_tap = 'op' + mgmt_bridge.removeprefix('br-op') + mgmt_suffix
        if not interface(mgmt_tap):
            call('ip', 'tuntap', 'add', 'dev', mgmt_tap, 'mode', 'tap')
        call('ip', 'link', 'set', mgmt_tap, 'master', mgmt_bridge)
        call('ip', 'link', 'set', mgmt_tap, 'up')
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


def _load_lifecycle_locks():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "opla_lifecycle_locks",
        Path(__file__).resolve().parent / "opla-lifecycle-lock.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lifecycle_locks = _load_lifecycle_locks()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'stop', 'status'))
    parser.add_argument('--lab', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Для операций с QEMU и TAP нужен sudo')
    state = load(args.lab)
    lab = Path(args.lab).resolve()
    with ExitStack() as stack:
        stack.enter_context(
            lifecycle_locks.lifecycle_lock(
                Path('/var/lib/opla') / '.opla-prune.lock'
            )
        )
        stack.enter_context(
            lifecycle_locks.lifecycle_lock(lab / 'maintenance.lock')
        )
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
