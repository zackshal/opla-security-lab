#!/usr/bin/env bash
# 200 HTTP-запросов через четыре постоянных соединения: отделяем L7 от SYN-теста.
set -euo pipefail
cd "$(dirname "$0")/.."
source xdp/lib.sh
victim_ip="$(get_victim_ip)"
attacker_ip="$(python3 bin/state.py "$LAB_DIR" ATTACKER_IP)"
mkdir -p reports
output_dir="$(mktemp -d reports/scenario-http-burst-XXXXXXXX)"
{ date -Is; printf 'LAB_DIR=%s\nvictim=%s\nrequests=200\nconnections=4\n' "$LAB_DIR" "$victim_ip"; } > "$output_dir/context.txt"
ssh_vm "$victim_ip" 'sudo python3 /tmp/xdp-build/collect.py' > "$output_dir/before.json"
result=0
ssh_vm "$attacker_ip" "python3 - $victim_ip" > "$output_dir/generator.json" <<'PY' || result=$?
import collections
import concurrent.futures
import http.client
import json
import sys
import time

def worker(_):
    counts = collections.Counter()
    connection = http.client.HTTPConnection(sys.argv[1], 80, timeout=3)
    try:
        for _ in range(50):
            try:
                connection.request('GET', '/')
                response = connection.getresponse()
                response.read()
                counts[str(response.status)] += 1
            except (OSError, http.client.HTTPException):
                counts['transport_error'] += 1
                connection.close()
    finally:
        connection.close()
    return counts

start = time.monotonic()
counts = collections.Counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    for row in pool.map(worker, range(4)):
        counts.update(row)
print(json.dumps({'requests': 200, 'results': dict(counts), 'seconds': time.monotonic()-start}))
sys.exit(int(bool(counts['transport_error'])))
PY
ssh_vm "$victim_ip" 'sudo python3 /tmp/xdp-build/collect.py' > "$output_dir/after.json"
cat "$output_dir/generator.json"
python3 - "$output_dir" <<'PY'
import json
from pathlib import Path
import sys
p=Path(sys.argv[1])
a=json.loads((p/'before.json').read_text()); b=json.loads((p/'after.json').read_text())
for k in ['syn','drop','http_requests','http_limited','http_5xx','http_parse_errors']:
    print(f'{k}: {a[k]} -> {b[k]}, delta={b[k]-a[k]}')
print('Материалы:', p)
PY
exit "$result"
