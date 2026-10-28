#!/usr/bin/env python3
"""Produce source-bound evidence from the actual service process tests.

Does not start VMs, SSH, Docker, privileged helpers or installed user units.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('bin/opla_service_runtime.py', 'bin/opla-service.py',
           'bin/opla-services.py', 'deploy/systemd/opla-service@.service',
           'bin/opla_service_operations.py', 'bin/opla-service-acceptance.py',
           'bin/opla-cli.py', 'bin/opla-incident-report.py', 'bin/opla-event-correlator.py',
           'bin/opla-eve-correlator.py',
           'bin/opla_service_contract.py', 'bin/opla_service_handlers.py',
           'bin/opla_service_transport.py', 'bin/opla-lab-orchestrator.py',
           'bin/opla-lab-progress.py', 'tests/test_service_process_runtime.py',
           'tests/test_service_acceptance_evidence.py', 'tests/fixtures/service_adapter.py')


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def verify_report(path):
    report = json.loads(Path(path).read_text(encoding='utf-8'))
    if (not isinstance(report, dict) or type(report.get('schema_version')) is not int
            or report['schema_version'] != 1 or report.get('status') != 'PASS'
            or report.get('source_unchanged') is not True
            or type(report.get('tests_run')) is not int or report['tests_run'] <= 0
            or any(type(report.get(key)) is not int or report[key] != 0
                   for key in ('failures', 'errors', 'skipped'))
            or report.get('live_lab_status') != 'NOT TESTED'):
        raise ValueError('report does not establish a successful process acceptance')
    if report.get('sources') != source_hashes():
        raise ValueError('stale report: checked sources differ from current code')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='new evidence file, never overwrite')
    parser.add_argument('--verify', type=Path, help='check report status and source freshness, not publisher authenticity')
    args = parser.parse_args()
    if args.verify:
        if args.output:
            parser.error('--verify and --output are mutually exclusive')
        try:
            report = verify_report(args.verify)
        except (OSError, ValueError) as exc:
            parser.exit(2, f'BLOCKED: {exc}\n')
        print(f'PASS: source hashes match {report["tests_run"]} process tests; live lab NOT TESTED')
        return 0
    if args.output is not None and (args.output.exists() or args.output.is_symlink()):
        parser.error('output already exists; choose a new evidence filename')
    sys.path.insert(0, str(ROOT))
    before = source_hashes()
    suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_service_process_runtime')
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    after = source_hashes()
    passed = result.wasSuccessful() and not result.skipped and before == after
    report = {'schema_version': 1, 'status': 'PASS' if passed else 'BLOCKED',
              'scope': 'local sockets/processes, synthetic lifecycle and real incident reporter',
              'live_lab_status': 'NOT TESTED', 'created_at': datetime.now(timezone.utc).isoformat(),
              'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
              'skipped': len(result.skipped), 'source_unchanged': before == after, 'sources': before}
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        with args.output.open('x', encoding='utf-8') as output:
            output.write(rendered)
    print(rendered, end='')
    return 0 if passed else 2


if __name__ == '__main__':
    sys.exit(main())
