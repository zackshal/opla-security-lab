#!/usr/bin/env python3
"""Read-only OPLA resource inventory and cleanup preview. Never deletes anything."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

LAB_ROOT = Path('/var/lib/opla')
VM_NAMES = ('attacker', 'victim', 'client')
LAB_PATTERN = re.compile(r'lab-[A-Za-z0-9]+\Z')
BRIDGE_PATTERN = re.compile(r'br-op[0-9]+\Z')


def validate_state(data, lab_name):
    if data.get('LAB_ID') != lab_name or not BRIDGE_PATTERN.fullmatch(data.get('BRIDGE', '')):
        raise ValueError('Invalid LAB_ID or BRIDGE')
    keys = ('MGMT_BRIDGE', 'MGMT_SUBNET', 'MGMT_GW',
            'ATTACKER_MGMT_IP', 'VICTIM_MGMT_IP', 'CLIENT_MGMT_IP')
    present = [key in data for key in keys]
    if not any(present):
        return data
    if not all(present) or not BRIDGE_PATTERN.fullmatch(data['MGMT_BRIDGE']) \
            or data['MGMT_BRIDGE'] == data['BRIDGE']:
        raise ValueError('Invalid management state')
    try:
        data_net = ipaddress.ip_network(data['SUBNET'])
        mgmt_net = ipaddress.ip_network(data['MGMT_SUBNET'])
    except (KeyError, ValueError) as exc:
        raise ValueError('Invalid data or management subnet') from exc
    allowed = ipaddress.ip_network('100.64.0.0/10')
    if (data_net.prefixlen != 29 or mgmt_net.prefixlen != 29
            or not data_net.subnet_of(allowed) or not mgmt_net.subnet_of(allowed)
            or data_net.overlaps(mgmt_net)):
        raise ValueError('Invalid or overlapping management subnet')
    for key in keys[2:]:
        if ipaddress.ip_address(data[key]) not in mgmt_net:
            raise ValueError('Management address outside subnet')
    return data


def call(*command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False)
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return -1, ''


def read_state(lab):
    # This is an inventory, never a justification to delete arbitrary paths.
    if lab.parent != LAB_ROOT or not LAB_PATTERN.fullmatch(lab.name) or lab.is_symlink():
        raise ValueError('Invalid lab path')
    file = lab / 'state.env'
    if file.is_symlink() or not file.is_file():
        raise ValueError('Missing or symlink state.env')
    state = {}
    for line in file.read_text(encoding='utf-8').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            state[key] = value
    return validate_state(state, lab.name)


def item(items, lab, kind, name, present, evidence, scope='lab', confidence='candidate'):
    items.append(dict(lab=lab, type=kind, name=name, present=present,
                      evidence=evidence, scope=scope, confidence=confidence))


def inventory(root=LAB_ROOT, inspect_runtime=True):
    records, warnings = [], []
    # Root is injected in tests. Runtime introspection is only valid on actual host.
    for lab in sorted(root.glob('lab-*')):
        if lab.is_symlink() or not lab.is_dir() or not LAB_PATTERN.fullmatch(lab.name):
            warnings.append(f'Skipped unsafe path: {lab}')
            continue
        try:
            # Preserve strict invariants while allowing an injectable root in unit tests.
            if root == LAB_ROOT:
                state = read_state(lab)
            else:
                state = parse_test_state(lab)
        except (OSError, ValueError, UnicodeError) as exc:
            warnings.append(f'{lab.name}: {exc}; no cleanup allowed')
            continue
        labid, bridge = lab.name, state['BRIDGE']
        item(records, labid, 'lab_directory', str(lab), True, 'validated state.env', confidence='observed')
        for vm in VM_NAMES:
            disk = lab / vm / 'disk.qcow2'
            seed = lab / vm / 'seed.iso'
            for name, path in (('disk', disk), ('cloud_init_iso', seed)):
                item(records, labid, name, str(path), path.is_file() and not path.is_symlink(),
                     'expected local path', confidence='candidate')
            unit = f'qemu-{labid}-{vm}.service'
            status = call('systemctl', 'is-active', '--quiet', unit)[0] == 0 if inspect_runtime else False
            item(records, labid, 'qemu_unit', unit, status, 'derived unit name')
            socket = lab / f'{vm}-qmp.sock'
            item(records, labid, 'qmp_socket', str(socket), socket.exists() and not socket.is_symlink(), 'expected local path')
        dhcp = f'dhcp-{labid}.service'
        item(records, labid, 'dhcp_unit', dhcp,
             call('systemctl', 'is-active', '--quiet', dhcp)[0] == 0 if inspect_runtime else False,
             'derived unit name')
        interfaces = [bridge] + ['op' + bridge.removeprefix('br-op') + c for c in 'avc']
        if state.get('MGMT_BRIDGE'):
            mgmt_bridge = state['MGMT_BRIDGE']
            interfaces += [mgmt_bridge] + ['op' + mgmt_bridge.removeprefix('br-op') + c for c in 'AVC']
        for name in interfaces:
            status = call('ip', 'link', 'show', 'dev', name)[0] == 0 if inspect_runtime else False
            item(records, labid, 'bridge' if name == bridge else 'tap', name, status, 'derived interface name')
        table = 'opla_' + labid.replace('-', '_')
        status = call('nft', 'list', 'table', 'inet', table)[0] == 0 if inspect_runtime else False
        item(records, labid, 'nft_table', table, status, 'derived table name')
        if state.get('MGMT_BRIDGE'):
            mgmt_table = 'opla_mgmt_' + labid.replace('-', '_')
            status = call('nft', 'list', 'table', 'inet', mgmt_table)[0] == 0 if inspect_runtime else False
            item(records, labid, 'nft_table', mgmt_table, status, 'derived management table name')
        # User units may belong to the invoking user or a different lab operator.
        item(records, labid, 'metrics_collector', f'opla-monitor-{labid}.service', None,
             'user-scoped unit; ownership unverified')
    # A creation receipt is not authorization to delete host resources.
    registry_dir = root / 'registry'
    if registry_dir.is_symlink():
        warnings.append('Unsafe registry symlink; registry records ignored')
    elif registry_dir.is_dir():
        for receipt_path in sorted(registry_dir.glob('lab-*.json')):
            if receipt_path.is_symlink() or not receipt_path.is_file():
                warnings.append(f'Unsafe registry receipt: {receipt_path.name}')
                continue
            try:
                receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
                labid = receipt_path.stem
                if (not LAB_PATTERN.fullmatch(labid) or
                    receipt.get('schema') != 1 or receipt.get('lab_id') != labid or
                    receipt.get('lab_dir') != str(root / labid)):
                    raise ValueError('receipt identity mismatch')
                item(records, labid, 'registry_receipt', str(receipt_path), True,
                     'OPLA creation receipt; host ownership not verified', confidence='recorded')
                if not (root / labid).is_dir():
                    warnings.append(f'{labid}: stale registry record (lab directory absent)')
            except (ValueError, OSError, TypeError, UnicodeError) as exc:
                warnings.append(f'Invalid receipt {receipt_path.name}: {exc}')
    # Shared resources are explicitly NOT included in a per-lab cleanup plan.
    item(records, None, 'compose_project', 'opla-monitoring', None,
         'name from monitoring/compose.yaml; Docker identity unverified', scope='shared')
    return records, warnings


def parse_test_state(lab):
    path = lab / 'state.env'
    if path.is_symlink():
        raise ValueError('Symlink state.env')
    data = dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)
    return validate_state(data, lab.name)


def render(items, warnings, action, lab=None, json_mode=False):
    chosen = [r for r in items if lab is None or r['lab'] == lab]
    payload = dict(mode=action, destructive=False, resources=chosen, warnings=warnings)
    if json_mode:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    print('OPLA RESOURCE INVENTORY — READ ONLY' if action == 'resources' else 'OPLA SECURE PRUNE — DRY RUN ONLY')
    print('No resources will be stopped, changed, or deleted.\n')
    if not chosen:
        print('No matching inventory records.')
    for record in chosen:
        present = ('?' if record['present'] is None else ('yes' if record['present'] else 'no'))
        print(f"{(record['lab'] or 'SHARED'):<20} {record['type']:<18} {present:<3} {record['name']}")
    if action == 'prune':
        print('\nDeletion blocked: ownership and dependency verification are not implemented.')
        print('Shared monitoring / Docker volumes are excluded from per-lab deletion.')
    for warning in warnings:
        print('WARNING:', warning, file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('resources', 'prune'))
    parser.add_argument('--lab', help='Exact lab-XXXXXXXX ID (no paths)')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    if args.lab and not LAB_PATTERN.fullmatch(args.lab):
        parser.error('LAB must be an ID like lab-XXXXXXXX')
    items, warnings = inventory()
    render(items, warnings, args.action, args.lab, args.json)
    return 0 if not warnings else 1


if __name__ == '__main__':
    sys.exit(main())
