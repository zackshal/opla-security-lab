#!/usr/bin/env python3
"""Record an actual CLI/service demonstration using synthetic evidence only."""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = ('bin/opla-cli.py', 'bin/opla-service.py', 'bin/opla-services.py',
                'bin/opla_service_runtime.py', 'bin/opla_service_operations.py',
                'bin/opla_service_contract.py', 'bin/opla_service_handlers.py',
                'bin/opla_service_transport.py', 'bin/opla-incident-report.py',
                'bin/opla-event-correlator.py', 'bin/opla-eve-correlator.py',
                'tools/record-service-demo.py')


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def record():
    before = source_hashes()
    steps = []
    with tempfile.TemporaryDirectory(prefix='opla-demo-') as temp:
        runtime = Path(temp) / 'opla'
        runtime.mkdir(mode=0o700)
        experiment = Path(temp) / 'demo-experiment'
        experiment.mkdir()
        interval = {'schema_version': 1, 'lab_id': 'lab-DEMO', 'clock_source': 'victim',
                    'start': '2026-10-27T13:00:00Z', 'end': '2026-10-27T13:00:10Z',
                    'source_ip': '100.64.0.2', 'target_ip': '100.64.0.3'}
        fixture = {'interval.json': interval,
                   'before.json': {'loaded': 1, 'syn': 100, 'drop': 0},
                   'after.json': {'loaded': 1, 'syn': 150, 'drop': 30}}
        for name, value in fixture.items():
            (experiment / name).write_text(json.dumps(value), encoding='utf-8')

        def run(arguments, expected=0):
            command = [sys.executable, str(ROOT / 'bin/opla-cli.py'), *arguments]
            started = time.monotonic()
            result = subprocess.run(command, cwd=temp, env={**os.environ, 'XDG_RUNTIME_DIR': temp},
                                    capture_output=True, text=True, timeout=15)
            display = ['python3', 'bin/opla-cli.py', *arguments]
            display = [str(arg).replace(str(experiment), '<experiment>') for arg in display]
            steps.append({'command': display, 'exit_code': result.returncode,
                          'stdout': result.stdout, 'stderr': result.stderr,
                          'elapsed_seconds': round(time.monotonic() - started, 3)})
            if result.returncode != expected:
                raise RuntimeError(f'demo step failed: {display}: {result.stderr}')
            return result

        run(['--help'])
        run(['system', 'services'])
        worker = subprocess.Popen([sys.executable, str(ROOT / 'bin/opla-service.py'),
                                   '--service', 'opla-evidence', '--socket', str(runtime / 'opla-evidence.sock')],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([worker.stdout], [], [], 5)
            if not ready or not worker.stdout.readline().startswith('LISTENING'):
                raise RuntimeError('evidence worker failed to start')
            result = run(['system', 'services'])
            if json.loads(result.stdout)['services']['opla-evidence']['status'] != 'RESPONDING':
                raise RuntimeError('evidence worker did not respond')
            result = run(['report', 'incident', str(experiment), '--via-service', '--lab', 'lab-DEMO'])
            report = json.loads(result.stdout)
            if (report['counters']['metrics']['xdp']['syn'] != 50
                    or report['evidence_quality']['complete_evidence_verified'] is not False):
                raise RuntimeError('report did not preserve expected counter delta/uncertainty')
            run(['report', 'incident', str(experiment), '--via-service', '--lab', 'lab-OTHER'], expected=2)
        finally:
            worker.terminate()
            try:
                worker.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.communicate(timeout=3)
        run(['system', 'services'])
    if before != source_hashes():
        raise RuntimeError('sources changed during demonstration')
    return {'schema_version': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
            'kind': 'actual local process recording with synthetic evidence',
            'live_vm_operations': False, 'fixture': fixture, 'sources': before,
            'source_unchanged': True, 'steps': steps}


def summary(step):
    args = step['command']
    if '--help' in args:
        return ['CLI help: lab, vm, deploy, xdp, ids, scenario, report, monitoring, system']
    if step['exit_code']:
        return [step['stderr'].strip(), f'exit code: {step["exit_code"]}']
    data = json.loads(step['stdout'])
    if 'services' in data:
        return [f'{name}: {value["status"]}' for name, value in data['services'].items()]
    return [f'SYN delta: {data["counters"]["metrics"]["xdp"]["syn"]}',
            f'Suricata: {data["suricata"]["status"]}',
            f'Complete evidence verified: {data["evidence_quality"]["complete_evidence_verified"]}']


def write_artifacts(directory, data):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'transcript.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['OPLA: recorded service demo / synthetic evidence / no VM operations', '']
    markdown = ['# Записанная демонстрация сервисов', '',
                'Это реальный вывод CLI и отдельных процессов с синтетическими evidence.',
                'VM, SSH, Docker и сетевые правила хоста не изменялись.', '',
                '![Визуализация записанного вывода](terminal.svg)', '',
                '[Полный stdout/stderr, exit codes, fixtures и hashes](transcript.json)', '']
    for index, step in enumerate(data['steps'], 1):
        command = ' '.join(step['command'])
        observed = summary(step)
        lines.extend(['$ ' + command, *observed, ''])
        markdown.extend([f'## Шаг {index}', '', '```text', '$ ' + command, *observed, '```', ''])
    markdown.extend(['SVG — визуализация сохранённого вывода, не скриншот и не измерение производительности.',
                     'Синтетический lab-DEMO не является созданной лабораторией.', ''])
    (directory / 'README.md').write_text('\n'.join(markdown), encoding='utf-8')
    width = max(1000, max(len(line) for line in lines) * 8 + 40)
    height = len(lines) * 21 + 40
    texts = ''.join(f'<text x="20" y="{30 + index * 21}" fill="{ "#86efac" if line.startswith("$") else "#e2e8f0" }">{html.escape(line)}</text>'
                    for index, line in enumerate(lines))
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
           '<title>OPLA actual local service demo with synthetic evidence</title>'
           f'<rect width="100%" height="100%" fill="#0f172a"/><g font-family="monospace" font-size="13">{texts}</g></svg>\n')
    (directory / 'terminal.svg').write_text(svg, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'assets/demo/services')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('record the demonstration as an ordinary user')
    write_artifacts(args.output, record())
    print(f'Recorded actual demonstration: {args.output}')


if __name__ == '__main__':
    main()
