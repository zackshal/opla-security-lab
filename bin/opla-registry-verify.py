#!/usr/bin/env python3
"""Fail-closed verification of OPLA creation receipts (read-only).

A receipt is evidence of the create operation, NOT exclusive ownership of
host resources. Never use the output to authorize automatic deletion.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('opla_registry', HERE / 'opla-registry.py')
reg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reg)


def probe(kind, name):
    """Return (status, detail): present/missing/unknown; never mutate host."""
    if kind in ('qcow2', 'cloud_init_iso', 'lab_directory'):
        path = Path(name)
        if path.is_symlink():
            return 'unsafe', 'symlink detected'
        if kind == 'lab_directory':
            return ('present' if path.is_dir() else 'missing'), 'filesystem'
        return ('present' if path.is_file() else 'missing'), 'filesystem'
    commands = {
        'bridge': ['ip', '-o', 'link', 'show', 'dev', name],
        'tap': ['ip', '-o', 'link', 'show', 'dev', name],
        'nft_table': ['nft', 'list', 'table', 'inet', name],
        'qemu_unit': ['systemctl', 'is-active', '--quiet', name],
        'dhcp_unit': ['systemctl', 'is-active', '--quiet', name],
    }
    if kind not in commands:
        return 'unknown', 'no supported probe'
    try:
        proc = subprocess.run(commands[kind], capture_output=True, text=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 'unknown', 'probe unavailable'
    if kind.endswith('_unit'):
        # Inactive does not imply that the unit does not exist.
        return ('active' if proc.returncode == 0 else 'inactive_or_unknown'), 'systemd'
    return ('present' if proc.returncode == 0 else 'missing_or_unreadable'), 'runtime'


def verify(root, labid=None, inspector=probe):
    root = Path(root)
    regdir = root / 'registry'
    if regdir.is_symlink():
        raise ValueError('registry directory is a symlink')
    if not regdir.is_dir():
        return []
    results = []
    for file in sorted(regdir.glob('lab-*.json')):
        if labid and file.name != labid + '.json':
            continue
        record = {'lab': file.stem, 'receipt': str(file), 'verified_for_deletion': False,
                  'status': 'blocked', 'checks': [], 'errors': []}
        results.append(record)
        if file.is_symlink() or not file.is_file():
            record['errors'].append('unsafe receipt path')
            continue
        try:
            data = json.loads(file.read_text(encoding='utf-8'))
            if (data.get('schema') != 1 or data.get('lab_id') != file.stem or
                    data.get('lab_dir') != str(root / file.stem) or
                    data.get('phase') not in ('creating', 'ready') or
                    not isinstance(data.get('resources'), list)):
                raise ValueError('receipt schema or identity mismatch')
            # Reconstruct expected resource set from verified state.env, not from
            # untrusted arbitrary resource paths in the receipt.
            expected = reg.receipt(root, file.stem, data['phase'])
            normalize = lambda seq: sorted((obj['kind'], obj['name']) for obj in seq)
            if normalize(data['resources']) != normalize(expected['resources']):
                raise ValueError('receipt resources differ from state.env')
            for resource in expected['resources']:
                status, detail = inspector(resource['kind'], resource['name'])
                record['checks'].append({'kind': resource['kind'], 'name': resource['name'],
                                         'status': status, 'source': detail,
                                         'ownership_verified': False})
            record['status'] = 'observed_unverified'
            record['errors'].append('host ownership and cross-lab dependencies not proven')
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
            record['errors'].append(str(exc))
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('verify', 'plan'))
    p.add_argument('--root', default='/var/lib/opla')
    p.add_argument('--lab')
    p.add_argument('--json', action='store_true')
    args = p.parse_args(argv)
    if args.lab and not reg.VALID.fullmatch(args.lab):
        p.error('invalid lab ID')
    results = verify(args.root, args.lab)
    if args.json:
        print(json.dumps({'destructive': False, 'labs': results, 'execution_allowed': False}, indent=2))
    else:
        print('OPLA REGISTRY VERIFICATION' if args.action == 'verify' else 'OPLA CLEANUP PLAN — BLOCKED / READ ONLY')
        if not results:
            print('No registry receipts found. Existing shared monitoring is NOT authorized for deletion.')
        for lab in results:
            print(f"{lab['lab']}: {lab['status']} ({len(lab['checks'])} observed resource checks)")
            for error in lab['errors']:
                print(f'  BLOCKED: {error}')
        if args.action == 'plan':
            print('No deletion performed; CONFIRM=yes cannot bypass these checks.')
    return 0 if all(x['status'] == 'observed_unverified' for x in results) else (1 if results else 0)

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f'OPLA verify: {exc}', file=sys.stderr)
        sys.exit(1)
