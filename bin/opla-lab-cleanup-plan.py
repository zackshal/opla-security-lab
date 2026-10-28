#!/usr/bin/env python3
"""Non-destructive preflight of a lab deletion; NEVER grants cleanup permission.

Existing destructive commands must refuse deletion while the new ownership
executor is incomplete. This avoids letting legacy cleanup bypass the registry.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

registry = load('opla_regplan_registry', 'opla-registry.py')
audit_module = load('opla_regplan_audit', 'opla-registry-audit.py')


def plan(root, lab):
    root = Path(root)
    if not registry.VALID.fullmatch(lab):
        raise ValueError('invalid lab ID')
    audit = audit_module.audit(root)
    receipt = root / 'registry' / (lab + '.json')
    reasons = []
    if audit['summary']['errors']:
        reasons.append('registry audit has errors or resource conflicts')
    if root.is_symlink() or (root / 'registry').is_symlink():
        reasons.append('unsafe registry root')
    if receipt.is_symlink() or not receipt.is_file():
        reasons.append('missing or unsafe creation receipt; legacy lab requires manual review')
    matching = [x for x in audit['labs'] if x['lab'] == lab]
    if len(matching) != 1 or matching[0]['status'] != 'observed_unverified':
        reasons.append('lab state and receipt are not consistently verified')
    if (root / lab).is_symlink() or not (root / lab).is_dir():
        reasons.append('lab directory absent or unsafe')
    reasons.append('exclusive ownership and dependency checks are not implemented')
    return {'schema': 1, 'lab': lab, 'destructive': False,
            'execution_allowed': False, 'reasons': reasons,
            'audit_summary': audit['summary']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='/var/lib/opla')
    parser.add_argument('--lab', required=True)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    result = plan(args.root, args.lab)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print('OPLA LAB DELETE PLAN — BLOCKED / READ ONLY')
        print('Lab:', result['lab'])
        for reason in result['reasons']:
            print('  BLOCKED:', reason)
        print('No deletion performed.')
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print('OPLA lab delete plan:', exc, file=sys.stderr)
        sys.exit(2)
