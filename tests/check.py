#!/usr/bin/env python3
"""Portable checks without QEMU, Docker, root or a live BPF subsystem."""
from pathlib import Path
import ast
import json
import shutil
import subprocess
import sys
import tempfile
R=Path(__file__).resolve().parents[1]
for p in R.rglob('*.sh'):
    if '.git' not in p.parts:subprocess.run(['bash','-n',str(p)],check=True)
for p in R.rglob('*.py'):
    if '.git' not in p.parts:ast.parse(p.read_text(),filename=str(p))
subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p','test_*.py','-v'],cwd=R,check=True)
if not shutil.which('cc'):sys.exit('Нужен C-компилятор для теста пакетов')
with tempfile.TemporaryDirectory(prefix='.opla-check-',dir=R) as tmp:
    target=str(Path(tmp)/'packets')
    subprocess.run(['cc','-O2','-Wall','-Werror','-Wno-unknown-pragmas','-Itests/stubs','tests/packet_harness.c','-o',target],cwd=R,check=True)
    subprocess.run([target],check=True)
try:
    import yaml
    for p in list((R/'cloud-init').glob('*.yaml'))+[R/'monitoring/compose.yaml']+list((R/'ansible').rglob('*.yml')):
        yaml.safe_load(p.read_text())
except ImportError: print('SKIP: YAML parser unavailable; run docker compose config on host')
print('PASS: shell syntax, Python syntax, monitoring tests, packet behavior')
print('NOT RUN: clang -target bpf, kernel verifier, KVM, live Zabbix API and dashboard')
