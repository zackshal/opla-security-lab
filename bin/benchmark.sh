#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/xdp/lib.sh"
count="${1:-100}"
[[ "$count" =~ ^[1-9][0-9]{0,3}$ ]] && ((count<=1000)) || { echo 'count: 1..1000'; exit 2; }
victim="$(get_victim_ip)"
client="$(python3 "$ROOT/bin/state.py" "$LAB_DIR" CLIENT_IP)"
mkdir -p "$ROOT/reports"
out="$(mktemp -d "$ROOT/reports/benchmark-XXXXXXXX")"
git -C "$ROOT" rev-parse HEAD > "$out/commit.txt"
git -C "$ROOT" diff --binary HEAD > "$out/working.patch"
ssh_vm "$victim" 'sudo python3 /tmp/xdp-build/collect.py' > "$out/before.json"
ssh_vm "$client" "python3 - '$victim' '$count'" > "$out/http.json" <<'PY'
import http.client,json,statistics,sys,time
host=sys.argv[1];count=int(sys.argv[2]);latencies=[];statuses={};failures=0
started=time.monotonic()
for _ in range(count):
    connection=http.client.HTTPConnection(host,80,timeout=3)
    begin=time.monotonic()
    try:
        connection.request('GET','/')
        response=connection.getresponse();response.read(1024*1024)
        statuses[str(response.status)]=statuses.get(str(response.status),0)+1
        latencies.append((time.monotonic()-begin)*1000)
    except (OSError,http.client.HTTPException): failures+=1
    finally: connection.close()
    time.sleep(.25)
elapsed=time.monotonic()-started
latencies.sort()
print(json.dumps({'requests':count,'statuses':statuses,'transport_errors':failures,
                  'elapsed_seconds':elapsed,'requests_per_second_including_pacing':count/elapsed,
                  'median_ms':statistics.median(latencies) if latencies else None,
                  'p95_ms':latencies[min(len(latencies)-1,int(.95*len(latencies)))] if latencies else None}))
PY
ssh_vm "$victim" 'sudo python3 /tmp/xdp-build/collect.py' > "$out/after.json"
cat "$out/http.json"
echo "Evidence: $out. This paced HTTP test is not an XDP pps benchmark."
