#!/usr/bin/env python3
"""Terminal documentation: concise help, detailed reference and paged manual."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs' / 'user-guide'

SECTIONS = [
    ('НАЧАЛО РАБОТЫ', [
        ('bootstrap', 'Скачать и проверить base image; не устанавливает host packages'),
        ('install', 'Установить команду opla для текущего пользователя'),
        ('uninstall', 'Удалить команду opla; VM и Docker не затрагиваются'),
        ('image ROLE=victim', 'Подготовить базовый образ Debian выбранной роли'),
        ('up', 'СОЗДАТЬ новый стенд; не запуск существующего'),
        ('ready', 'Дождаться cloud-init на всех трёх узлах через SSH'),
    ]),
    ('ВЫБОР СТЕНДА И УЗЛОВ', [
        ('labs', 'Список стендов и состояние процессов QEMU'),
        ('lab-select LAB=lab-...', 'Сохранить выбор стенда для текущего пользователя'),
        ('lab-status', 'Показать выбранный стенд и его узлы'),
        ('lab-start', 'Восстановить сеть и запустить сохранённые VM без пересоздания дисков'),
        ('lab-stop', 'Выключить VM, DHCP и удалить TAP/bridge/nft; сохранить диски'),
        ('lab-delete LAB=lab-... CONFIRM_DELETE=lab-...', 'Verified удаление конкретного стенда и дисков'),
        ('lab-infra-status', 'Состояние виртуальных машин, bridge и DHCP'),
        ('lab-stack-down', 'Дополнительно остановить общий Zabbix/PostgreSQL (все стенды!)'),
        ('stack-down', 'Синоним lab-stack-down; влияет на общий мониторинг'),
        ('nodes', 'Показать роли, IP и состояние QEMU'),
        ('ssh VM=victim', 'SSH в victim, attacker или client'),
        ('console VM=victim', 'Последовательная консоль выбранной VM'),
        ('down', 'BLOCKED: legacy cleanup; для остановки используйте lab-stop'),
    ]),
    ('ЗАЩИТА', [
        ('xdp-all', 'Скопировать, собрать и загрузить XDP на victim'),
        ('xdp-stats', 'Получить счётчики XDP/HTTP/IDS через collector'),
        ('xdp-unload', 'Отключить XDP на victim'),
        ('ids / ips / ids-off', 'Включить обнаружение / блокирование / выключить Suricata'),
        ('ids-status / ids-test', 'Состояние и проверка Suricata'),
    ]),
    ('МОНИТОРИНГ', [
        ('monitoring-up', 'Запустить контейнеры Zabbix/PostgreSQL'),
        ('monitoring-configure', 'Настроить объекты Zabbix через API'),
        ('monitoring-start', 'Запустить сборщик метрик выбранного стенда'),
        ('monitoring-stop', 'Остановить сборщик выбранного стенда'),
        ('monitoring-down', 'Остановить Zabbix и сборщики; volume БД сохраняется'),
    ]),
    ('СНИМКИ И РЕЗЕРВИРОВАНИЕ', [
        ('vm-save VM=client TAG=name', 'Создать QMP-снимок работающей VM'),
        ('vm-snapshots VM=client', 'Перечислить QMP-снимки VM'),
        ('vm-load VM=client TAG=name ROLLBACK=yes', 'ОТКАТИТЬ VM: потеря изменений после снимка'),
        ('vm-delete VM=client TAG=name', 'Удалить QMP-снимок, не саму VM'),
        ('vm-backup BACKUP_DIR=/path', 'Создать автономные копии дисков только после остановки VM'),
        ('vm-resume', 'Запустить сохранённые VM после штатного выключения'),
        ('backup-db BACKUP_DIR=/path', 'Сделать pg_dump PostgreSQL'),
    ]),
    ('ДОКУМЕНТАЦИЯ И ПРОВЕРКИ', [
        ('resources', 'Инвентаризация ресурсов OPLA без изменений системы'),
        ('resources LAB=lab-...', 'Инвентаризация выбранного стенда'),
        ('prune', 'Только план очистки (dry-run); удаление запрещено'),
        ('doctor', 'Предварительная диагностика зависимостей и QEMU'),
        ('runtime-audit', 'Static matrix P14–P21; не запускает инфраструктуру'),
        ('host-admission-export OUTPUT=file', 'Read-only export dedicated host; не создаёт VM и не меняет сеть'),
        ('host-admission-import REPORT=file EXPECTED_HOST_ID=hex EXPECTED_COLLECTOR_SHA256=hex DECISION=file', 'Проверить export без system probes и сохранить решение'),
        ('check', 'Переносимые тесты; не заменяют испытания KVM/BPF'),
        ('versions', 'Показать версии компонентов'),
        ('manual', 'Открыть полноэкранное руководство (less)'),
        ('help-full', 'Подробный справочник команд'),
        ('help-xdp / help-vm', 'Тематические руководства'),
    ]),
]


def brief():
    print('OPLA SECURITY LAB — справка по командам Makefile')
    print('Рекомендуемый интерфейс: opla --help')
    print('Справка по подсистеме: opla lab --help | opla scenario --help')
    print('Ниже приведены команды Makefile для разработки и совместимости.')
    print('Все команды выполняются из корня репозитория. make up СОЗДАЁТ стенд.')
    print('make down заблокирован. lab-stop сохраняет диски; lab-delete удаляет их после проверок.\n')
    for title, entries in SECTIONS:
        print(f'[{title}]')
        for command, description in entries:
            print(f'  make {command:<43} {description}')
        print()
    print('Выбор: make labs → make lab-select LAB=lab-... → make nodes')
    print('Полный текст: make manual | make help-full | make help-xdp | make help-vm')


def view(path):
    if not path.is_file():
        raise FileNotFoundError(path)
    if sys.stdout.isatty() and shutil.which('glow'):
        return subprocess.call(['glow', '-p', str(path)])
    if sys.stdout.isatty() and shutil.which('less'):
        env = dict(os.environ)
        env.setdefault('LESS', '-R')
        return subprocess.call(['less', str(path)], env=env)
    sys.stdout.write(path.read_text(encoding='utf-8'))
    return 0


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else 'help'
    pages = {
        'manual': DOCS / 'manual.md',
        'help-full': DOCS / 'commands.md',
        'help-xdp': DOCS / 'xdp.md',
        'help-vm': DOCS / 'virtual-machines.md',
    }
    if action == 'help':
        brief()
        return 0
    if action not in pages:
        print(f'Неизвестная тема: {action}', file=sys.stderr)
        return 2
    return view(pages[action])


if __name__ == '__main__':
    sys.exit(main())
