#!/usr/bin/env python3
import argparse
import ipaddress
import json
import struct
import subprocess

PIN = '/sys/fs/bpf/opla/maps/xdp_policy'
MODES = {'off': 0, 'observe': 1, 'block': 2}

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

def main():
    p = argparse.ArgumentParser(description='Set runtime XDP scan policy; resets on XDP reload')
    p.add_argument('--mode', choices=MODES, required=True)
    p.add_argument('--trusted-source', action='append', default=[])
    a = p.parse_args()
    try:
        value = encode(a.mode, a.trusted_source)
        info = json.loads(subprocess.check_output(['bpftool', '-j', 'map', 'show', 'pinned', PIN], text=True))
        if isinstance(info, list):
            info = info[0]
        if info['type'] != 'hash' or info.get('bytes_key') != 4 or info.get('bytes_value') != 12 or info['max_entries'] != 1:
            raise ValueError('Unexpected XDP policy map ABI; no changes made')
        subprocess.run(['bpftool', 'map', 'update', 'pinned', PIN,
                        'key', 'hex', '00', '00', '00', '00',
                        'value', 'hex', *[f'{byte:02x}' for byte in value]], check=True)
        print(json.dumps({'mode': a.mode, 'trusted_sources': a.trusted_source,
                          'threshold': 8, 'fixed_window_seconds': 60, 'block_seconds': 30,
                          'scope': 'new IPv4 TCP SYN only; trusted sources bypass scan policy only'}))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        p.exit(1, str(error) + '\n')

if __name__ == '__main__':
    main()
