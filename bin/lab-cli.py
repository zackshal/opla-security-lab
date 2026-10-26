#!/usr/bin/env python3
"""Read-only lab discovery and explicit per-user selection for OPLA."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from state import load, latest

ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = Path('/var/lib/opla')
SELECTION = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'opla' / 'selected-lab'
VMS = ('attacker', 'victim', 'client')


def validate(value):
    if not re.fullmatch(r'lab-[A-Za-z0-9]+', value):
        raise ValueError('Ожидается идентификатор вида lab-XXXXXXXX')
    path = LAB_ROOT / value
    return path, load(str(path))


def selected():
    if not SELECTION.is_file():
        return None
    if SELECTION.is_symlink():
        raise ValueError('Файл выбора стенда не должен быть символической ссылкой')
    value = SELECTION.read_text().strip()
    return validate(value)[0]


def current():
    explicit = os.environ.get('LAB_DIR', '').strip()
    if explicit:
        path = Path(explicit)
        if path.parent != LAB_ROOT:
            raise ValueError('LAB_DIR должен быть путём /var/lib/opla/lab-...')
        return validate(path.name)[0]
    chosen = selected()
    if chosen is not None:
        return chosen
    recent = latest()
    if recent:
        return validate(Path(recent).name)[0]
    raise ValueError('Стенды не найдены: сначала make up')


def unit_active(unit):
    try:
        result = subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=3, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def list_labs():
    try:
        chosen = selected()
    except (OSError, ValueError) as exc:
        print(f'Предупреждение: выбор стенда некорректен: {exc}', file=sys.stderr)
        chosen = None
    rows = []
    for state_file in sorted(LAB_ROOT.glob('lab-*/state.env')):
        path = state_file.parent
        try:
            data = load(str(path))
            count = sum(unit_active(f'qemu-{data["LAB_ID"]}-{vm}.service') for vm in VMS)
            rows.append((path.name, f'{count}/3 VM', data['SUBNET'], '*' if chosen == path else ''))
        except (OSError, ValueError, KeyError) as exc:
            rows.append((path.name, 'INVALID', str(exc), ''))
    if not rows:
        print('Стендов нет. Создать новый: make up')
        return
    print(f'{"STAND":<22} {"RUNNING":<10} {"SUBNET / ERROR":<35} SELECTED')
    for name, state, network, flag in rows:
        print(f'{name:<22} {state:<10} {network:<35} {flag}')
    print('\n* — выбранный стенд; состояние ВМ определяется по systemd, не по наличию диска.')


def select_lab(value):
    if value == 'latest':
        value = Path(latest()).name
    path, _ = validate(value)
    SELECTION.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if SELECTION.is_symlink():
        raise ValueError('Небезопасный путь к файлу выбора')
    temp = SELECTION.with_name(SELECTION.name + f'.{os.getpid()}.tmp')
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(path.name + '\n')
        os.replace(temp, SELECTION)
    finally:
        temp.unlink(missing_ok=True)
    print(f'Выбран стенд: {path}')
    print('Переменная LAB_DIR из окружения имеет приоритет над сохранённым выбором.')


def print_nodes():
    path = current()
    data = load(str(path))
    print(f'Стенд: {path}\n')
    print(f'{"NODE":<12} {"IP":<17} {"QEMU":<10} SSH')
    for vm in VMS:
        unit = f'qemu-{data["LAB_ID"]}-{vm}.service'
        running = unit_active(unit)
        print(f'{vm:<12} {data[vm.upper() + "_IP"]:<17} {"RUNNING" if running else "STOPPED":<10} не проверялся')
    print('\nПодключение: make ssh VM=victim (или attacker/client)')
    print('Для проверки SSH: make ready (дожидается cloud-init).')


def doctor():
    errors = 0
    print('OPLA — диагностика хоста и выбранного стенда\n')
    for name in ('python3', 'make', 'qemu-system-x86_64', 'qemu-img', 'ip', 'nft', 'ssh', 'docker'):
        ok = shutil.which(name) is not None
        print(f'{"OK  " if ok else "WARN"} {name}')
    print(f'{"OK  " if Path("/dev/kvm").exists() else "WARN"} /dev/kvm (наличие, не проверка доступа)')
    try:
        path = current()
        data = load(str(path))
        print(f'OK   выбранный стенд: {path}')
        for vm in VMS:
            active = unit_active(f'qemu-{data["LAB_ID"]}-{vm}.service')
            print(f'{"OK  " if active else "WARN"} QEMU {vm}: {"работает" if active else "не работает"}')
    except (ValueError, OSError, KeyError) as exc:
        print(f'WARN стенд: {exc}')
        errors += 1
    print('\nЭто предварительная диагностика; SSH, BPF, IDS и Zabbix здесь не проверяются.')
    return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('list', 'select', 'current', 'nodes', 'doctor'))
    parser.add_argument('lab', nargs='?', help='lab-ID или latest для select')
    args = parser.parse_args()
    try:
        if args.action == 'list':
            list_labs()
        elif args.action == 'select':
            if not args.lab:
                parser.error('Пример: make lab-select LAB=lab-ZV3bwu5z')
            select_lab(args.lab)
        elif args.action == 'current':
            print(current())
        elif args.action == 'nodes':
            print_nodes()
        elif args.action == 'doctor':
            return doctor()
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(2, f'Ошибка: {exc}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
