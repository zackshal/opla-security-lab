#!/usr/bin/env python3
import argparse
import datetime
import importlib.util
import json
from pathlib import Path
import sys
import time
from bridge import send, append_log
from catalog import METRICS, item_key

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('local_collect', ROOT/'xdp/collect.py')
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', required=True)
    p.add_argument('--interval', type=float, default=5)
    p.add_argument('--once', action='store_true')
    a = p.parse_args()
    if a.interval < 1:
        p.error('interval >= 1')
    log = Path('/var/log/opla/events.jsonl')
    log.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    previous = None
    while True:
        begin = time.monotonic()
        try:
            now = int(time.time())
            data = collect.full_snapshot()
            if any(type(data.get(k)) is not int or data[k] < 0 for k in METRICS):
                raise ValueError('Invalid snapshot')
            event = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     'event': 'snapshot', 'host': a.host, 'metrics': data}
            append_log(log, event)
            records = [{'host': a.host, 'key': item_key(k), 'value': str(data[k]), 'clock': now} for k in METRICS]
            records += [{'host': a.host, 'key': 'xdp.mode', 'value': data['mode'], 'clock': now}]
            watched = ['loaded', 'mode', 'ids_up', 'ids_alerts', 'ids_blocked', 'drop', 'http_limited']
            if previous is None or any(data[k] != previous[k] for k in watched):
                records += [{'host': a.host, 'key': 'xdp.events', 'value': json.dumps(event), 'clock': now}]
            send(records)
            previous = data
        except Exception as error:
            print(type(error).__name__ + ': collection or delivery failed', file=sys.stderr, flush=True)
            if a.once:
                return 1
        if a.once:
            return 0
        time.sleep(max(0, a.interval-(time.monotonic()-begin)))

if __name__ == '__main__':
    sys.exit(main())
