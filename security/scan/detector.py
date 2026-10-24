#!/usr/bin/env python3
"""Passive, bounded IPv4 SYN destination-port detector after XDP."""
import argparse
from collections import OrderedDict
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import time

ROOT = Path('/var/lib/opla-scan')
STATUS = Path('/run/opla-scan/status.json')
LOG = Path('/var/log/opla-scan/events.jsonl')


def parse_syn(frame):
    if len(frame) < 14:
        return None
    proto = struct.unpack_from('!H', frame, 12)[0]
    offset = 14
    for _ in range(2):
        if proto not in (0x8100, 0x88a8):
            break
        if len(frame) < offset + 4:
            return None
        proto = struct.unpack_from('!H', frame, offset + 2)[0]
        offset += 4
    if proto != 0x0800 or len(frame) < offset + 20:
        return None
    version_ihl = frame[offset]
    ihl = (version_ihl & 15) * 4
    total = struct.unpack_from('!H', frame, offset + 2)[0]
    fragment = struct.unpack_from('!H', frame, offset + 6)[0]
    if (version_ihl >> 4 != 4 or ihl < 20 or total < ihl + 20
            or len(frame) < offset + total or fragment & 0x3fff or frame[offset + 9] != 6):
        return None
    tcp = offset + ihl
    header = (frame[tcp + 12] >> 4) * 4
    flags = frame[tcp + 13]
    if header < 20 or ihl + header > total or not flags & 2 or flags & (1 | 4 | 16):
        return None
    source = socket.inet_ntoa(frame[offset + 12:offset + 16])
    target = socket.inet_ntoa(frame[offset + 16:offset + 20])
    port = struct.unpack_from('!H', frame, tcp + 2)[0]
    return source, target, port


class Detector:
    def __init__(self, target, threshold=8, window=60, max_pairs=1024, max_ports=64, counters=None):
        self.target = str(ipaddress.IPv4Address(target))
        if not 2 <= threshold <= max_ports <= 256 or not 1 <= window <= 3600 or not 1 <= max_pairs <= 4096:
            raise ValueError('Invalid detector bounds')
        self.threshold, self.window = threshold, window
        self.max_pairs, self.max_ports = max_pairs, max_ports
        self.pairs = OrderedDict()
        self.counters = dict(alerts=0, capture_drops=0, evictions=0, **{})
        if counters:
            for key in self.counters:
                value = counters.get(key, 0)
                if type(value) is not int or value < 0:
                    raise ValueError('Invalid persistent counter')
                self.counters[key] = value
        self.last = 'No port-scan event observed'

    def expire(self, now):
        for pair, entry in list(self.pairs.items()):
            ports = entry['ports']
            for port, seen in list(ports.items()):
                if now - seen >= self.window:
                    del ports[port]
            if len(ports) < self.threshold:
                entry['active'] = False
            if not ports:
                del self.pairs[pair]

    def observe(self, source, target, port, now):
        if target != self.target or source == target:
            return None
        key = source, target
        if key not in self.pairs:
            if len(self.pairs) >= self.max_pairs:
                self.pairs.popitem(last=False)
                self.counters['evictions'] += 1
            self.pairs[key] = dict(ports=OrderedDict(), active=False)
        self.pairs.move_to_end(key)
        entry = self.pairs[key]
        ports = entry['ports']
        for old_port, seen in list(ports.items()):
            if now - seen >= self.window:
                del ports[old_port]
        if len(ports) < self.threshold:
            entry['active'] = False
        if port not in ports and len(ports) >= self.max_ports:
            ports.popitem(last=False)
        ports[port] = now
        ports.move_to_end(port)
        if len(ports) >= self.threshold and not entry['active']:
            entry['active'] = True
            self.counters['alerts'] += 1
            self.last = f'{source} -> {target}: {len(ports)} distinct TCP ports / {self.window}s'
            return dict(source_ip=source, destination_ip=target, distinct_ports=len(ports),
                        sample_ports=list(ports)[:16], window_seconds=self.window,
                        event='tcp_port_scan_suspected', action='alert')
        return None

    def snapshot(self, now):
        self.expire(now)
        return dict(scan_up=1, scan_active=sum(x['active'] for x in self.pairs.values()),
                    scan_alerts=self.counters['alerts'], scan_capture_drops=self.counters['capture_drops'],
                    scan_evictions=self.counters['evictions'], scan_details=self.last,
                    pairs=len(self.pairs), threshold=self.threshold, window_seconds=self.window,
                    target=self.target, monotonic=now)


def atomic_json(filename, data):
    filename.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = filename.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(filename)


def append_event(path, event):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and path.stat().st_size >= 5 * 1024 * 1024:
        path.replace(path.with_suffix('.jsonl.1'))
    with path.open('a') as stream:
        stream.write(json.dumps(dict(timestamp=int(time.time()), **event)) + '\n')


def run(args):
    os.umask(0o077)
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    counter_file = ROOT / 'counters.json'
    counters = json.loads(counter_file.read_text()) if counter_file.exists() else None
    detector = Detector(args.target, args.threshold, args.window, counters=counters)
    stopped = False

    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with (ROOT / 'detector.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as capture:
            capture.bind((args.interface, 0))
            capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            capture.settimeout(0.2)
            try:
                capture.setsockopt(263, 23, 1)  # PACKET_IGNORE_OUTGOING
            except OSError:
                pass
            next_tick = 0.0
            last_saved = None
            while not stopped:
                try:
                    frame, address = capture.recvfrom(65535)
                    if address[2] != socket.PACKET_OUTGOING:
                        parsed = parse_syn(frame)
                        if parsed:
                            event = detector.observe(*parsed, time.monotonic())
                            if event:
                                atomic_json(counter_file, detector.counters)
                                append_event(LOG, event)
                except socket.timeout:
                    pass
                now = time.monotonic()
                if now >= next_tick:
                    stats = capture.getsockopt(263, 6, 8)  # PACKET_STATISTICS, read resets socket counters
                    _, dropped = struct.unpack('II', stats)
                    detector.counters['capture_drops'] += dropped
                    if last_saved != detector.counters:
                        atomic_json(counter_file, detector.counters)
                        last_saved = detector.counters.copy()
                    atomic_json(STATUS, detector.snapshot(now))
                    next_tick = now + 1
            final = detector.snapshot(time.monotonic())
            final['scan_up'] = 0
            atomic_json(counter_file, detector.counters)
            atomic_json(STATUS, final)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--interface', default='ens3')
    parser.add_argument('--threshold', type=int, default=8)
    parser.add_argument('--window', type=int, default=60)
    run(parser.parse_args())
