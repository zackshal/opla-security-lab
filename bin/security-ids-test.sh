#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/xdp/lib.sh"
victim="$(get_victim_ip)"
client="$(python3 "$ROOT/bin/state.py" "$LAB_DIR" CLIENT_IP)"
mkdir -p "$ROOT/reports"
out="$(mktemp -d "$ROOT/reports/ids-acceptance-XXXXXXXX")"
ssh_vm "$victim" 'sudo python3 /tmp/xdp-build/collect.py' > "$out/before.json"
set +e
ssh_vm "$client" "curl --max-time 5 -sS -o /dev/null -w 'HTTP=%{http_code}\n' 'http://$victim/__opla_block_test__'" > "$out/marker.txt" 2>&1
result=$?
set -e
printf '%s\n' "$result" > "$out/marker-exit-code.txt"
sleep 2
ssh_vm "$client" "curl --max-time 3 -sS -o /dev/null -w 'HTTP=%{http_code}\n' 'http://$victim/'" > "$out/normal.txt" 2>&1
ssh_vm "$victim" 'sudo python3 /tmp/xdp-build/collect.py' > "$out/after.json"
cat "$out/marker.txt" "$out/normal.txt"
echo "Evidence: $out. IDS should alert; IPS should block marker. Correlate EVE SID 9001100/9001200 and ids.blocked."
