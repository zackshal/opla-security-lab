#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PIN = os.environ.get('OPLA_BPF_PIN', '/sys/fs/bpf/opla') + '/maps/syn_windows'

def decode(entry, now_ns):
    raw = entry['key']
    source = str(ipaddress.IPv4Address(bytes(int(x, 0) if isinstance(x, str) else x for x in raw)))
    value = entry.get('formatted', {}).get('value')
    if value is None:
        blob = bytes(int(x, 0) if isinstance(x, str) else x for x in entry['value'])
        value = {'count': int.from_bytes(blob[4:8], sys.byteorder),
                 'start_ns': int.from_bytes(blob[8:16], sys.byteorder)}
    return {'source_ip': source, 'window_count': value['count'],
            'window_age_seconds': max(0, now_ns - value['start_ns']) / 1e9}

def main():
    p = argparse.ArgumentParser(description='Read-only source IP map; run inside victim')
    p.add_argument('--limit', type=int, default=20)
    a = p.parse_args()
    if not 1 <= a.limit <= 65536:
        p.error('limit 1..65536')
    info = json.loads(subprocess.check_output(['bpftool', '-j', 'map', 'show', 'pinned', PIN], text=True, timeout=5))
    capacity = (info[0] if isinstance(info,list) else info)['max_entries']
    rows = json.loads(subprocess.check_output(['bpftool', '-j', 'map', 'dump', 'pinned', PIN], text=True, timeout=10))
    now = time.monotonic_ns()
    result = sorted((decode(row, now) for row in rows), key=lambda x: x['window_count'], reverse=True)
    print(json.dumps({'entries': len(rows), 'capacity': capacity, 'sources': result[:a.limit],
                      'note': 'Window age is not last-seen age; no automatic eviction.'}, indent=2))

if __name__ == '__main__':
    main()
