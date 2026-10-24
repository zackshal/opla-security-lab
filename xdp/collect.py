#!/usr/bin/env python3
"""Один снимок pinned maps. trace_pipe не читаем: он общий и разрушающий."""
import json
import fcntl
import http.client
import time
import os
from pathlib import Path
import subprocess
import sys

HTTP_COUNTERS = ['http_requests', 'http_limited', 'http_5xx', 'http_parse_errors']

def http_snapshot(log_path=Path('/var/log/nginx/opla-security.jsonl'),
                  state_dir=Path('/var/lib/opla-telemetry')):
    """Читаем новые полные строки, а не весь журнал при каждом опросе."""
    empty = dict.fromkeys(HTTP_COUNTERS, 0)
    if not log_path.exists():
        return dict(http_available=0, **empty)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state_dir/'http.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state_file = state_dir/'http.json'
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        counters = {k: int(state.get(k, 0)) for k in HTTP_COUNTERS}
        with log_path.open('rb') as stream:
            stat = os.fstat(stream.fileno())
            identity = [stat.st_dev, stat.st_ino]
            offset = int(state.get('offset', 0))
            if state.get('identity') != identity or offset > stat.st_size:
                offset = 0
            stream.seek(offset)
            chunk = stream.read(1024*1024)
            complete = chunk.rfind(b'\n') + 1
            for raw in chunk[:complete].splitlines():
                try:
                    row = json.loads(raw)
                    status = int(row['status'])
                    if not 100 <= status <= 599:
                        raise ValueError('HTTP status outside range')
                    counters['http_requests'] += 1
                    counters['http_limited'] += int(row.get('limit_req') == 'REJECTED')
                    counters['http_5xx'] += int(status >= 500)
                except (ValueError, KeyError, TypeError):
                    counters['http_parse_errors'] += 1
            state = dict(counters, identity=identity, offset=offset+complete)
        temporary = state_file.with_suffix('.tmp')
        temporary.write_text(json.dumps(state))
        temporary.replace(state_file)
        return dict(http_available=1, **counters)

def ids_snapshot(log_path=Path('/var/log/opla-suricata/eve.json'),
                 state_dir=Path('/var/lib/opla-telemetry'), enabled=None, up=None):
    if enabled is None:
        enabled = int(Path('/etc/opla-suricata/mode.json').exists())
    if up is None:
        up = int(subprocess.run(['systemctl', 'is-active', '--quiet', 'opla-suricata.service'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=2).returncode == 0)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state_dir/'ids.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state_file = state_dir/'ids.json'
        saved = json.loads(state_file.read_text()) if state_file.exists() else {}
        keys = ['ids_alerts', 'ids_blocked', 'ids_parse_errors', 'ids_kernel_drops']
        counters = {key: int(saved.get(key, 0)) for key in keys}
        if not log_path.exists():
            return dict(ids_enabled=enabled, ids_up=up, **counters)
        with log_path.open('rb') as stream:
            st = os.fstat(stream.fileno())
            identity = [st.st_dev, st.st_ino]
            offset = int(saved.get('offset', 0))
            if saved.get('identity') != identity or offset > st.st_size:
                offset = 0
            stream.seek(offset)
            chunk = stream.read(1024*1024)
            complete = chunk.rfind(b'\n') + 1
            for raw in chunk[:complete].splitlines():
                try:
                    row = json.loads(raw)
                    kind = row['event_type']
                    if kind == 'alert':
                        counters['ids_alerts'] += 1
                        counters['ids_blocked'] += int(row.get('alert', {}).get('action') == 'blocked')
                    elif kind == 'stats':
                        capture = row.get('stats', {}).get('capture')
                        if isinstance(capture, dict) and 'kernel_drops' in capture:
                            counters['ids_kernel_drops'] = int(capture['kernel_drops'])
                except (ValueError, TypeError, KeyError):
                    counters['ids_parse_errors'] += 1
            saved = dict(counters, identity=identity, offset=offset+complete)
        temporary = state_file.with_suffix('.tmp')
        temporary.write_text(json.dumps(saved))
        temporary.replace(state_file)
        return dict(ids_enabled=enabled, ids_up=up, **counters)

def scan_snapshot(status_path=Path('/run/opla-scan/status.json'),
                  marker=Path('/etc/opla-scan/enabled'),
                  counters_path=Path('/var/lib/opla-scan/counters.json'), now=None):
    result = dict(scan_enabled=int(marker.exists()), scan_up=0, scan_active=0,
                  scan_alerts=0, scan_capture_drops=0, scan_evictions=0,
                  scan_details='Detector unavailable or disabled')
    def counters(data):
        for source, dest in [('alerts', 'scan_alerts'), ('capture_drops', 'scan_capture_drops'), ('evictions', 'scan_evictions')]:
            value = data.get(source, 0)
            if type(value) is int and value >= 0:
                result[dest] = value
    try:
        if counters_path.exists():
            counters(json.loads(counters_path.read_text()))
        if not result['scan_enabled']:
            return result
        status = json.loads(status_path.read_text())
        age = (time.monotonic() if now is None else now) - float(status['monotonic'])
        if not 0 <= age <= 10 or status.get('scan_up') != 1:
            return result
        keys = ['scan_active', 'scan_alerts', 'scan_capture_drops', 'scan_evictions']
        if any(type(status.get(k)) is not int or status[k] < 0 for k in keys):
            return result
        result.update({k: status[k] for k in keys})
        result['scan_up'] = 1
        result['scan_details'] = str(status.get('scan_details', 'No event'))[:250]
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass
    return result


def full_snapshot():
    data = snapshot()
    # Это счётчики драйвера, а не гарантированное число пакетов до XDP.
    for key in ['rx_packets', 'rx_bytes']:
        data[key] = int(Path('/sys/class/net', os.environ.get('OPLA_INTERFACE', 'ens3'), 'statistics', key).read_text())
    data.update(http_probe())
    data.update(http_snapshot())
    data.update(ids_snapshot())
    data.update(scan_snapshot())
    return data

def http_probe():
    """Проверка внутри victim; внешнюю доступность с client измеряют отдельно."""
    started = time.monotonic_ns()
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=1)
    status = 0
    try:
        connection.request('GET', '/')
        response = connection.getresponse()
        status = response.status
        response.read(4096)
    except (OSError, http.client.HTTPException):
        pass
    finally:
        connection.close()
    return {'http_up': int(status == 200), 'http_status': status,
            'http_latency_us': max(0, (time.monotonic_ns()-started)//1000)}

PIN=os.environ.get('OPLA_BPF_PIN', '/sys/fs/bpf/opla')
KEYS=['syn','pass','drop','map_full','fragment_drop']

def number(value):
    if isinstance(value,int): return value
    if isinstance(value,str): return int(value,0)
    if isinstance(value,list):
        raw=bytes(int(x,0) if isinstance(x,str) else x for x in value)
        return int.from_bytes(raw,sys.byteorder)
    raise ValueError(f'Неподдерживаемый формат bpftool: {value!r}')

def run(*args):
    return json.loads(subprocess.check_output(args,text=True,timeout=5))

def attachment_mode(link, program_id):
    """iproute2 может возвращать attached строкой или списком программ."""
    labels = {1: 'native', 2: 'generic', 3: 'offload'}
    raw = link.get('attached')
    fallback = {'drv': 'native', 'native': 'native',
                'skb': 'generic', 'generic': 'generic', 'hw': 'offload'}
    candidates = [link]
    if isinstance(raw, list):
        candidates.extend(entry for entry in raw if isinstance(entry, dict))
    for entry in candidates:
        found = entry.get('prog', {}).get('id', entry.get('prog_id'))
        if found is not None and int(found) == int(program_id):
            code = entry.get('mode', link.get('mode'))
            if code in labels:
                return labels[code]
            if isinstance(raw, str) and raw in fallback:
                return fallback[raw]
    raise ValueError('Режим прикреплённой программы не определён')

def snapshot():
    link=run('ip','-j','link','show','dev',os.environ.get('OPLA_INTERFACE', 'ens3'))[0].get('xdp',{})
    active=bool(link) and link.get('attached', 'off') not in ('off', 0)
    if not active: return dict(loaded=0,mode='off',**{k:0 for k in KEYS})
    prog=run('bpftool','-j','prog','show','pinned',PIN+'/program')
    if isinstance(prog,list): prog=prog[0]
    mode=attachment_mode(link, prog['id'])
    entries=run('bpftool','-j','map','dump','pinned',PIN+'/maps/xdp_stats')
    stats={k:0 for k in KEYS}
    for entry in entries:
        index=number(entry['key'])
        if not 0<=index<len(KEYS): raise ValueError('Неизвестный индекс счётчика')
        if 'values' in entry:
            value=sum(number(v['value']) for v in entry['values'])
        elif 'value' in entry: value=number(entry['value'])
        else: raise ValueError('Нет значения счётчика')
        stats[KEYS[index]]=value
    return dict(loaded=1,mode=mode,**stats)

if __name__=='__main__':
    try: print(json.dumps(full_snapshot()))
    except (OSError,ValueError,subprocess.SubprocessError) as e:
        print(str(e),file=sys.stderr);sys.exit(1)
