#!/usr/bin/env bash
# Запускаем конечный сценарий только между ВМ выбранного стенда.
set -euo pipefail
cd "$(dirname "$0")/.."
source xdp/lib.sh
scenario="${1:-}"
victim_ip="$(get_victim_ip)"
attacker_ip="$(python3 bin/state.py "$LAB_DIR" ATTACKER_IP)"
case "$scenario" in
    syn) command_text="sudo hping3 -q -n -S -p 80 -i u1000 -c 2000 $victim_ip" ;;
    ack) command_text="sudo hping3 -q -n -A -p 80 -i u2000 -c 1000 $victim_ip" ;;
    udp) command_text="sudo hping3 -q -n --udp -p 9999 -i u2000 -c 1000 $victim_ip" ;;
    icmp) command_text="sudo hping3 -q -n --icmp -i u10000 -c 100 $victim_ip" ;;
    http) command_text="for i in \$(seq 1 100); do curl --max-time 3 -sS -o /dev/null -w '%{http_code} %{time_total}\\n' http://$victim_ip/ || exit \$?; done" ;;
    *) echo 'Использование: bash bin/traffic-scenario.sh syn|ack|udp|icmp|http' >&2; exit 2 ;;
esac
mkdir -p reports
output_dir="$(mktemp -d "reports/scenario-$scenario-XXXXXXXX")"
{
    date -Is
    printf 'LAB_DIR=%s\nscenario=%s\nvictim=%s\nattacker=%s\ncommand=%s\n' \
        "$LAB_DIR" "$scenario" "$victim_ip" "$attacker_ip" "$command_text"
    echo 'Порог берите из команды последней сборки; изменение THRESHOLD без сборки его не меняет.'
    sha256sum xdp/xdp_ddos_protect.c
} > "$output_dir/context.txt"
scp_vm "$victim_ip" /tmp/xdp-build/ "$PROJECT_DIR/xdp/fingerprint.py"

ssh_vm "$victim_ip" 'sudo python3 /tmp/xdp-build/fingerprint.py inspect' > "$output_dir/fingerprint-before.json"
ssh_vm "$victim_ip" 'sudo python3 /tmp/xdp-build/collect.py' > "$output_dir/before.json"
# Use the victim clock for the experiment interval.
started_at="$(ssh_vm "$victim_ip" 'date -u +%Y-%m-%dT%H:%M:%S.%NZ')"

result=0
ssh_vm "$attacker_ip" "$command_text" > "$output_dir/generator.txt" 2>&1 || result=$?

finished_at="$(ssh_vm "$victim_ip" 'date -u +%Y-%m-%dT%H:%M:%S.%NZ')"

python3 - "$output_dir/interval.json" "$started_at" "$finished_at" "$attacker_ip" "$victim_ip" <<'INTERVAL'
import ipaddress
import json
import sys
from datetime import datetime

path, start, end, attacker, victim = sys.argv[1:]

a = datetime.fromisoformat(start.replace("Z", "+00:00"))
b = datetime.fromisoformat(end.replace("Z", "+00:00"))

if a.tzinfo is None or b.tzinfo is None or b < a:
    raise ValueError("Invalid experiment timestamps")

data = {
    "schema_version": 1,
    "clock_source": "victim",
    "start": start,
    "end": end,
    "source_ip": str(ipaddress.ip_address(attacker)),
    "target_ip": str(ipaddress.ip_address(victim)),
}

with open(path, "x", encoding="utf-8") as stream:
    json.dump(data, stream, indent=2)
    print(file=stream)
INTERVAL

ssh_vm "$victim_ip" 'sudo python3 /tmp/xdp-build/collect.py' > "$output_dir/after.json"
ssh_vm "$victim_ip" 'sudo python3 /tmp/xdp-build/fingerprint.py inspect' > "$output_dir/fingerprint-after.json"
printf '%s\n' "$result" > "$output_dir/generator-exit.txt"
python3 - "$output_dir" <<'PY'
import json
import sys
from pathlib import Path
p = Path(sys.argv[1])
a = json.loads((p/'before.json').read_text())
b = json.loads((p/'after.json').read_text())
keys = ['syn', 'pass', 'drop', 'map_full', 'fragment_drop']
if a['loaded'] != 1 or b['loaded'] != 1:
    print('XDP отключён в одном из снимков; дельты могут быть несопоставимы.')
for k in keys:
    delta = b[k] - a[k]
    print(f'{k}: {a[k]} -> {b[k]}, delta={delta}')
    if delta < 0:
        print('Счётчик сбросился: этот опыт нужно повторить без перезагрузки XDP.')
print('Материалы опыта:', p)
PY
printf 'Код завершения генератора: %s (см. generator.txt)\n' "$result"
exit "$result"
