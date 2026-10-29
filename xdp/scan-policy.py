#!/usr/bin/env python3
import argparse
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import stat
import struct
import subprocess
from contextlib import contextmanager
import errno

PIN = '/sys/fs/bpf/opla/maps/xdp_policy'
MAP_PIN_ROOT = Path('/sys/fs/bpf/opla/maps')
PROGRAM_PIN = '/sys/fs/bpf/opla/program'
LOAD_RECEIPT = Path('/tmp/xdp-build/load-receipt.json')
LOCK_PATH = Path('/run/lock/opla-xdp.lock')
MODES = {'off': 0, 'observe': 1, 'block': 2}
DEFAULT_BPFTool_TIMEOUT = 5.0
LOAD_RECEIPT_SCHEMA = 2
EXPECTED_MAP_NAMES = {'syn_windows', 'xdp_stats', 'xdp_policy'}
MAX_RECEIPT_BYTES = 64 * 1024


def validate_timeout(timeout):
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError('bpftool timeout must be finite and positive')
    return timeout


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate load receipt JSON key')
        result[key] = value
    return result


def reject_json_constant(value):
    raise ValueError(f'invalid load receipt JSON constant: {value}')

def encode(mode, trusted):
    if mode not in MODES or len(trusted) > 2:
        raise ValueError('Expected off/observe/block and at most two trusted IPv4 sources')
    addresses = [ipaddress.IPv4Address(address).packed for address in trusted]
    if mode != 'off' and len(set(addresses)) != 2:
        raise ValueError('Provide two distinct trusted IPv4 sources (management and client)')
    for address in addresses:
        ip = ipaddress.IPv4Address(address)
        if ip.is_unspecified or ip.is_multicast or str(ip) == '255.255.255.255':
            raise ValueError('Trusted source must be a unicast IPv4 address')
    return struct.pack('=I', MODES[mode]) + b''.join(addresses).ljust(8, b'\0')


def validate_map_abi(info):
    """Require one unambiguous bpftool map description with exact integer ABI."""
    if isinstance(info, list):
        if len(info) != 1:
            raise ValueError('Unexpected XDP policy map ABI; no changes made')
        info = info[0]
    if not isinstance(info, dict) or info.get('type') != 'hash':
        raise ValueError('Unexpected XDP policy map ABI; no changes made')
    expected = {'bytes_key': 4, 'bytes_value': 12, 'max_entries': 1}
    for field, value in expected.items():
        actual = info.get(field)
        if type(actual) is not int or actual != value:
            raise ValueError('Unexpected XDP policy map ABI; no changes made')
    return info


def validate_policy_map_identity(map_info, receipt, program_info, observed_maps,
                                 attached_program_id):
    if isinstance(program_info, list):
        if len(program_info) != 1:
            raise ValueError('Unexpected OPLA program identity; no changes made')
        program_info = program_info[0]
    attached_ids = ([attached_program_id] if type(attached_program_id) is int
                    else attached_program_id)
    if (not isinstance(attached_ids, list) or not attached_ids
            or any(type(item) is not int or item <= 0 for item in attached_ids)
            or not isinstance(receipt, dict) or receipt.get('schema_version') not in {1, LOAD_RECEIPT_SCHEMA}
            or not isinstance(program_info, dict)
            or type(receipt.get('program_id')) is not int
            or type(program_info.get('id')) is not int or program_info['id'] <= 0
            or receipt.get('program_id') != program_info.get('id')
            or receipt.get('program_tag') != program_info.get('tag')
            or program_info.get('id') not in attached_ids):
        raise ValueError('Load receipt does not identify the pinned OPLA program; no changes made')
    program_map_ids = program_info.get('map_ids')
    receipt_map_ids = receipt.get('program_map_ids')
    has_receipt_map_ids = receipt.get('schema_version') == LOAD_RECEIPT_SCHEMA or receipt_map_ids is not None
    if (not isinstance(program_map_ids, list) or not program_map_ids
            or any(type(item) is not int or item <= 0 for item in program_map_ids)
            or len(set(program_map_ids)) != len(program_map_ids)
            or (has_receipt_map_ids
                and (not isinstance(receipt_map_ids, list)
                     or any(type(item) is not int or item <= 0 for item in receipt_map_ids)
                     or len(set(receipt_map_ids)) != len(receipt_map_ids)
                     or receipt_map_ids != sorted(program_map_ids)))):
        raise ValueError('Pinned program map IDs differ from load receipt; no changes made')
    if not isinstance(observed_maps, dict) or set(observed_maps) != EXPECTED_MAP_NAMES:
        raise ValueError('Pinned map inventory is incomplete; no changes made')
    if (any(not isinstance(entry, dict) or type(entry.get('id')) is not int
            or entry['id'] <= 0 or not isinstance(entry.get('type'), str)
            for entry in observed_maps.values())
            or {entry['id'] for entry in observed_maps.values()} != set(program_map_ids)):
        raise ValueError('Pinned map IDs differ from the loaded OPLA program; no changes made')
    maps = receipt.get('maps')
    has_receipt_maps = receipt.get('schema_version') == LOAD_RECEIPT_SCHEMA or maps is not None
    if (type(map_info.get('id')) is not int or map_info['id'] <= 0
            or map_info.get('id') != observed_maps['xdp_policy'].get('id')
            or map_info.get('type') != observed_maps['xdp_policy'].get('type')
            or (has_receipt_maps
                and (not isinstance(maps, dict) or set(maps) != EXPECTED_MAP_NAMES
                     or any(not isinstance(entry, dict)
                            or type(entry.get('id')) is not int or entry['id'] <= 0
                            or not isinstance(entry.get('type'), str)
                            or entry.get('id') != observed_maps[name].get('id')
                            or entry.get('type') != observed_maps[name].get('type')
                            for name, entry in maps.items())))):
        raise ValueError('Pinned scan-policy map differs from load receipt; no changes made')


def load_receipt():
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = None
    try:
        fd = os.open(LOAD_RECEIPT, flags)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != 0 or info.st_mode & 0o022
                or info.st_size > MAX_RECEIPT_BYTES):
            raise ValueError('load receipt has unsafe file identity')
        chunks = []
        remaining = MAX_RECEIPT_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        if len(raw) > MAX_RECEIPT_BYTES:
            raise ValueError('load receipt exceeds size limit')
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=reject_duplicate_keys,
                          parse_constant=reject_json_constant)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f'load receipt unavailable: {error}') from None
    finally:
        if fd is not None:
            os.close(fd)
    if not isinstance(data, dict):
        raise ValueError('load receipt is malformed')
    return data


def pinned_program():
    result = json.loads(subprocess.check_output(
        ['bpftool', '-j', 'prog', 'show', 'pinned', PROGRAM_PIN],
        text=True, timeout=DEFAULT_BPFTool_TIMEOUT))
    if isinstance(result, list):
        if len(result) != 1:
            raise ValueError('Unexpected OPLA program identity; no changes made')
        result = result[0]
    if not isinstance(result, dict):
        raise ValueError('Unexpected OPLA program identity; no changes made')
    return result


def attached_program_id(timeout=DEFAULT_BPFTool_TIMEOUT):
    payload = json.loads(subprocess.check_output(
        ['ip', '-j', 'link', 'show', 'dev', 'ens3'], text=True, timeout=timeout))
    if (not isinstance(payload, list) or len(payload) != 1
            or not isinstance(payload[0], dict) or payload[0].get('ifname') != 'ens3'):
        raise ValueError('Cannot establish ens3 attachment identity; no changes made')
    xdp = payload[0].get('xdp')
    if not isinstance(xdp, dict):
        raise ValueError('No known XDP attachment on ens3; no changes made')
    attached = xdp.get('attached')
    known_modes = {'drv', 'native', 'skb', 'generic', 'hw', 'offload'}
    ids = []
    if isinstance(attached, str):
        if attached not in known_modes:
            raise ValueError('No known XDP attachment on ens3; no changes made')
    elif isinstance(attached, list) and attached and all(isinstance(item, str) for item in attached):
        if any(item not in known_modes for item in attached):
            raise ValueError('No known XDP attachment on ens3; no changes made')
    elif isinstance(attached, list) and attached:
        # iproute2 JSON uses [{"mode": N, "prog": {"id": N, ...}}, ...].
        for item in attached:
            if (not isinstance(item, dict) or type(item.get('mode')) is not int
                    or item['mode'] not in {1, 2, 3}
                    or not isinstance(item.get('prog'), dict)):
                raise ValueError('Malformed ens3 XDP attachment list; no changes made')
            ids.append(item['prog'].get('id'))
    elif type(attached) is int:
        if attached not in {1, 2, 3, 4}:
            raise ValueError('No known XDP attachment on ens3; no changes made')
    elif type(xdp.get('mode')) is int:
        if xdp['mode'] not in {1, 2, 3, 4}:
            raise ValueError('No known XDP attachment on ens3; no changes made')
    else:
        raise ValueError('No known XDP attachment on ens3; no changes made')
    if 'prog_id' in xdp:
        ids.append(xdp['prog_id'])
    if 'prog' in xdp:
        prog = xdp['prog']
        if not isinstance(prog, dict) or 'id' not in prog:
            raise ValueError('Malformed ens3 XDP program identity; no changes made')
        ids.append(prog['id'])
    if not ids or any(type(item) is not int or item <= 0 for item in ids):
        raise ValueError('Incomplete ens3 XDP program identity; no changes made')
    ids = list(dict.fromkeys(ids))
    return ids[0] if len(ids) == 1 else ids


def pinned_map_inventory(timeout=DEFAULT_BPFTool_TIMEOUT):
    maps = {}
    for name in sorted(EXPECTED_MAP_NAMES):
        result = json.loads(subprocess.check_output(
            ['bpftool', '-j', 'map', 'show', 'pinned', str(MAP_PIN_ROOT / name)],
            text=True, timeout=timeout))
        if isinstance(result, list):
            if len(result) != 1:
                raise ValueError('Unexpected pinned map identity; no changes made')
            result = result[0]
        if (not isinstance(result, dict) or type(result.get('id')) is not int
                or result['id'] <= 0 or not isinstance(result.get('type'), str)):
            raise ValueError('Unexpected pinned map identity; no changes made')
        maps[name] = {'id': result['id'], 'type': result['type']}
    if len({entry['id'] for entry in maps.values()}) != len(maps):
        raise ValueError('Duplicate pinned map identities; no changes made')
    return maps


def safe_lock_directory(info, effective_uid):
    if not stat.S_ISDIR(info.st_mode):
        return False
    if info.st_uid == effective_uid and not (info.st_mode & 0o022):
        return True
    # A root-owned sticky directory (Debian may expose /run/lock this way)
    # prevents non-root users replacing the root-owned lock inode.
    return (effective_uid == 0 and info.st_uid == 0
            and bool(info.st_mode & stat.S_ISVTX)
            and bool(info.st_mode & 0o002))


@contextmanager
def policy_lock():
    try:
        parent = LOCK_PATH.parent.lstat()
    except OSError as error:
        raise ValueError(f'XDP lifecycle lock directory unavailable: {error}') from None
    if not safe_lock_directory(parent, os.geteuid()):
        raise ValueError('XDP lifecycle lock directory has unsafe identity or permissions')
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(LOCK_PATH, flags, 0o600)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError('XDP lifecycle lock must not be a symlink') from None
        raise
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError('XDP lifecycle lock has unsafe file identity or permissions')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('another OPLA XDP lifecycle operation is active') from None
        yield
    finally:
        os.close(fd)

def main(*, timeout=DEFAULT_BPFTool_TIMEOUT):
    p = argparse.ArgumentParser(description='Set runtime XDP scan policy; resets on XDP reload')
    p.add_argument('--mode', choices=MODES, required=True)
    p.add_argument('--trusted-source', action='append', default=[])
    a = p.parse_args()
    try:
        timeout = validate_timeout(timeout)
        value = encode(a.mode, a.trusted_source)
        with policy_lock():
            info = json.loads(subprocess.check_output(
                ['bpftool', '-j', 'map', 'show', 'pinned', PIN], text=True,
                timeout=timeout))
            info = validate_map_abi(info)
            receipt = load_receipt()
            validate_policy_map_identity(info, receipt, pinned_program(),
                                         pinned_map_inventory(timeout),
                                         attached_program_id(timeout))
            subprocess.run(['bpftool', 'map', 'update', 'pinned', PIN,
                            'key', 'hex', '00', '00', '00', '00',
                            'value', 'hex', *[f'{byte:02x}' for byte in value]],
                           check=True, timeout=timeout)
        print(json.dumps({'mode': a.mode, 'trusted_sources': a.trusted_source,
                          'threshold': 8, 'fixed_window_seconds': 60, 'block_seconds': 30,
                          'scope': 'new IPv4 TCP SYN only; trusted sources bypass scan policy only'}))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        p.exit(1, str(error) + '\n')

if __name__ == '__main__':
    main()
