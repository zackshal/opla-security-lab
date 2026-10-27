#!/usr/bin/env python3
"""Unified OPLA Security Lab CLI."""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

GROUPS = {
    "lab": "Создание, выбор и управление лабораториями",
    "vm": "Виртуальные машины, снимки и резервирование",
    "xdp": "Загрузка XDP и просмотр телеметрии",
    "ids": "Управление Suricata",
    "scenario": "Проверка и выполнение сценариев",
    "report": "Отчёты по экспериментам и инцидентам",
    "monitoring": "Мониторинг Zabbix",
    "system": "Установка, диагностика и обслуживание",
}

# Action -> (Makefile target, description, argument definitions).
# Argument: (CLI flag or positional name, Makefile variable).
COMMANDS = {
    "lab": {
        "list": ("labs", "Список лабораторий", []),
        "status": ("lab-status", "Статус выбранной лаборатории", []),
        "select": ("lab-select", "Выбрать лабораторию", [("lab", "LAB")]),
        "nodes": ("nodes", "Узлы выбранной лаборатории", []),
        "start": ("lab-start", "Запустить сохранённый стенд", []),
        "stop": ("lab-stop", "Остановить стенд, сохранив диски", []),
        "infra": ("lab-infra-status", "Состояние инфраструктуры", []),
        "create": ("up", "Создать новый стенд", []),
        "ready": ("ready", "Дождаться cloud-init на узлах", []),
        "delete": ("lab-delete", "Безвозвратно удалить стенд", [("lab", "LAB")]),
    },
    "vm": {
        "ssh": ("ssh", "Подключиться к VM", [("--vm", "VM")]),
        "console": ("console", "Открыть консоль VM", [("--vm", "VM")]),
        "snapshots": ("vm-snapshots", "Список снимков", [("--vm", "VM")]),
        "save": ("vm-save", "Создать снимок", [("--vm", "VM"), ("--tag", "TAG")]),
        "load": ("vm-load", "Восстановить снимок", [("--vm", "VM"), ("--tag", "TAG")]),
        "delete": ("vm-delete", "Удалить снимок", [("--vm", "VM"), ("--tag", "TAG")]),
        "backup": ("vm-backup", "Скопировать диски", [("--backup-dir", "BACKUP_DIR")]),
        "resume": ("vm-resume", "Запустить сохранённые VM", []),
    },
    "xdp": {
        "deploy": ("xdp-deploy", "Скопировать исходники XDP", []),
        "build": ("xdp-build", "Собрать XDP в VM", []),
        "load": ("xdp-load", "Загрузить XDP на victim", []),
        "all": ("xdp-all", "Развернуть, собрать и загрузить XDP", []),
        "unload": ("xdp-unload", "Отключить XDP", []),
        "stats": ("xdp-stats", "Счётчики XDP и IDS", []),
    },
    "ids": {
        "enable": ("ids", "Включить Suricata IDS", []),
        "block": ("ips", "Включить режим IPS", []),
        "disable": ("ids-off", "Выключить Suricata", []),
        "status": ("ids-status", "Показать состояние", []),
        "test": ("ids-test", "Проверить Suricata", []),
    },
    "scenario": {
        "validate": ("scenario-validate", "Проверить YAML-сценарий", [("scenario", "SCENARIO")]),
        "plan": ("scenario-plan", "Показать план сценария", [("scenario", "SCENARIO")]),
        "simulate": ("scenario-simulate", "Симулировать сценарий", [("scenario", "SCENARIO")]),
        "check": ("scenario-live-check", "Проверить live-исполнитель", [("scenario", "SCENARIO"), ("--lab", "LAB")]),
        "run": ("scenario-live-run", "Запустить live-сценарий", [("scenario", "SCENARIO"), ("--lab", "LAB"), ("--confirm", "CONFIRM")]),
    },
    "report": {
        "bundle": ("experiment-bundle", "Собрать пакет доказательств эксперимента", [("path", "REPORT")]),
        "experiment": ("experiment-report", "Отчёт SYN-эксперимента", [("path", "REPORT")]),
        "compare": ("experiment-compare", "Сравнить архивные эксперименты", [("--reports", "REPORTS"), ("--format", "FORMAT")]),
        "incident": ("incident-report", "Корреляция XDP и IDS", [("path", "REPORT"), ("--eve", "EVE"), ("--scan-events", "SCAN_EVENTS")]),
    },
    "monitoring": {
        "publish": ("monitoring-experiment-publish", "Отправить событие эксперимента в Zabbix", [("--lab", "LAB"), ("--experiment", "REPORT")]),
        "up": ("monitoring-up", "Запустить мониторинг", []),
        "configure": ("monitoring-configure", "Настроить Zabbix API", []),
        "start": ("monitoring-start", "Запустить сбор метрик", []),
        "stop": ("monitoring-stop", "Остановить сбор метрик", []),
        "down": ("monitoring-down", "Остановить мониторинг", []),
    },
    "system": {
        "bootstrap": ("bootstrap", "Подготовить хост", []),
        "doctor": ("doctor", "Проверить зависимости", []),
        "check": ("check", "Запустить тесты", []),
        "versions": ("versions", "Версии компонентов", []),
        "resources": ("resources", "Инвентаризация ресурсов", []),
        "prune": ("prune", "План очистки без удаления", []),
        "manual": ("manual", "Руководство пользователя", []),
        "image": ("image", "Подготовить образ роли", [("--role", "ROLE")]),
    },
}

SAFE_VALUE = re.compile(r"^[A-Za-z0-9_./:@+-]+$")
LAB_ID = re.compile(r"^lab-[A-Za-z0-9_-]+$")

LEGACY = {
    "labs": "opla lab list",
    "lab-select": "opla lab select lab-ID",
    "scenario-simulate": "opla scenario simulate",
    "xdp-stats": "opla xdp stats",
    "ids-status": "opla ids status",
}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="opla",
        description="OPLA Security Lab — управление изолированными лабораториями",
        epilog="Справка: opla help <раздел> | opla <раздел> --help",
    )
    parser.add_argument(
        "--version", action="version", version="OPLA Security Lab (development)"
    )
    groups = parser.add_subparsers(dest="group")
    group_parsers = {}

    for group, description in GROUPS.items():
        gp = groups.add_parser(group, help=description, description=description)
        group_parsers[group] = gp
        actions = gp.add_subparsers(dest="action")

        for action, (target, explanation, arguments) in COMMANDS[group].items():
            command = actions.add_parser(
                action,
                help=explanation,
                description=f"{explanation}. Makefile target: {target}",
            )
            command.set_defaults(target=target, arguments=arguments)

            for name, variable in arguments:
                if name.startswith("--"):
                    options = {"required": False}
                    if variable == "FORMAT":
                        options["choices"] = ("json", "csv")
                        options["default"] = "csv"
                    elif variable == "REPORTS":
                        options["default"] = "reports"
                    elif variable == "VM":
                        options["choices"] = ("victim", "attacker", "client")
                        options["default"] = "victim"
                    elif variable == "ROLE":
                        options["choices"] = ("victim", "attacker", "client")
                        options["required"] = True
                    elif variable in ("LAB", "CONFIRM", "TAG", "BACKUP_DIR", "REPORT"):
                        options["required"] = True
                    command.add_argument(name, **options)
                else:
                    options = {}
                    if variable == "SCENARIO":
                        options = {"nargs": "?", "default": "syn-scan-baseline"}
                    command.add_argument(name, **options)

            if group == "monitoring" and action == "publish":
                command.add_argument("--dry-run", action="store_true")
            if group == "lab" and action == "create":
                command.add_argument("--confirm-host-changes", action="store_true")
            if group == "system" and action == "bootstrap":
                command.add_argument("--confirm-host-changes", action="store_true")
            if group == "lab" and action == "delete":
                command.add_argument("--confirm-lab", required=True)
            if group == "vm" and action == "load":
                command.add_argument("--rollback", action="store_true")

    return parser, group_parsers


def make_command(args):
    group = args.group
    action = args.action

    if (group, action) in (("lab", "create"), ("system", "bootstrap")):
        if not args.confirm_host_changes:
            raise ValueError(
                "Операция изменяет хост. Требуется --confirm-host-changes"
            )

    variables = []

    if group == "monitoring" and action == "publish" and args.dry_run:
        variables.append("DRY_RUN=1")

    for name, variable in args.arguments:
        value = getattr(args, name.lstrip("-").replace("-", "_"), None)
        if value is None:
            continue
        value = str(value)
        if not SAFE_VALUE.fullmatch(value):
            raise ValueError(
                f"Недопустимое значение {name}: разрешены безопасные символы без пробелов"
            )
        variables.append(f"{variable}={value}")

    if group == "lab" and action in ("select", "delete"):
        if not LAB_ID.fullmatch(args.lab):
            raise ValueError("Ожидается ID лаборатории вида lab-XXXXXXXX")

    if group == "lab" and action == "delete":
        if args.lab != args.confirm_lab:
            raise ValueError("Подтверждение должно точно совпадать с ID лаборатории")
        variables.append(f"CONFIRM_DELETE={args.confirm_lab}")

    if group == "vm" and action == "load":
        if not args.rollback:
            raise ValueError("Откат VM требует явного флага --rollback")
        variables.append("ROLLBACK=yes")

    return [
        "make", "--no-print-directory", "-C", str(ROOT),
        args.target, *variables,
    ]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "help":
        argv = argv[1:] + ["--help"] if len(argv) > 1 else ["--help"]

    if argv and argv[0] in LEGACY:
        print(
            f"Устаревший вызов. Используйте: {LEGACY[argv[0]]}",
            file=sys.stderr,
        )
        return 2

    parser, group_parsers = build_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse uses SystemExit(0) for --help and --version.
        # Keep main() usable as a testable Python entry point.
        return int(exc.code) if isinstance(exc.code, int) else 2

    if not args.group:
        parser.print_help()
        return 0

    if not args.action:
        group_parsers[args.group].print_help()
        return 0

    try:
        command = make_command(args)
    except ValueError as exc:
        print(f"OPLA: {exc}", file=sys.stderr)
        return 2

    try:
        return subprocess.run(command, check=False).returncode
    except OSError as exc:
        print(f"OPLA: ошибка запуска: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
