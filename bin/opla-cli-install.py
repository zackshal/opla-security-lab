#!/usr/bin/env python3
"""Install/remove only the per-user OPLA command; never modify VMs or packages."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path.home() / ".local" / "bin" / "opla"
MARKER = "# OPLA_CLI_WRAPPER_V1"

def content():
    # Quoting handles repository paths containing spaces or apostrophes.
    import shlex
    return ("#!/bin/sh\n" + MARKER + "\n" +
            "exec make --no-print-directory -C " + shlex.quote(str(ROOT)) + ' "$@"\n')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('install', 'uninstall'))
    args = p.parse_args()
    target = TARGET
    if target.is_symlink():
        sys.exit('Отказ: ~/.local/bin/opla является символьной ссылкой; проверьте её вручную')
    if args.action == 'install':
        if target.exists() and MARKER not in target.read_text(errors='replace'):
            sys.exit(f'Отказ: {target} уже занят другой утилитой')
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        tmp = target.with_name('opla.tmp.' + str(os.getpid()))
        try:
            with tmp.open('x') as f:
                f.write(content())
            tmp.chmod(0o755)
            tmp.replace(target)
        finally:
            tmp.unlink(missing_ok=True)
        print('Установлено:', target)
        print('Команда: opla help (или make help из каталога репозитория)')
        if str(target.parent) not in os.environ.get('PATH','').split(':'):
            print('Добавьте ~/.local/bin в PATH вашей оболочки')
    else:
        if not target.exists():
            print('Команда opla не установлена')
            return
        if MARKER not in target.read_text(errors='replace'):
            sys.exit('Отказ: файл не распознан как OPLA wrapper')
        target.unlink()
        print('CLI удалён. Репозиторий, VM, образы и Docker volumes не затронуты.')

if __name__ == '__main__':
    main()
