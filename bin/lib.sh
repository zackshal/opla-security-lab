#!/usr/bin/env bash
find_free_bridge() {
    local i=0
    while [[ "br-op$i" == "${OPLA_EXCLUDE_BRIDGE:-}" ]] ||
        ip link show "br-op$i" >/dev/null 2>&1 ||
        grep -qsE "^(BRIDGE|MGMT_BRIDGE)=br-op$i$" /var/lib/opla/lab-*/state.env 2>/dev/null; do
        i=$((i+1))
    done
    echo "br-op$i"
}
find_free_subnet_excluding() {
    local excluded="${1:-}"
    OPLA_EXCLUDE_SUBNET="$excluded" python3 - <<'PYCODE'
import ipaddress,json,os,subprocess
routes=json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all']))
occupied=[ipaddress.ip_network(r['dst'],strict=False) for r in routes if r.get('dst','default')!='default']
excluded=os.environ.get('OPLA_EXCLUDE_SUBNET','')
if excluded:
    occupied.append(ipaddress.ip_network(excluded, strict=False))
for net in ipaddress.ip_network('100.64.0.0/10').subnets(new_prefix=29):
    if not any(net.overlaps(n) for n in occupied):
        print(net.network_address); break
else: raise SystemExit('Нет свободной /29')
PYCODE
}
find_free_subnet() {
    python3 - <<'PYCODE'
import ipaddress,json,subprocess
routes=json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all']))
occupied=[ipaddress.ip_network(r['dst'],strict=False) for r in routes if r.get('dst','default')!='default']
for net in ipaddress.ip_network('100.64.0.0/10').subnets(new_prefix=29):
    if not any(net.overlaps(n) for n in occupied):
        print(net.network_address); break
else: raise SystemExit('Нет свободной /29')
PYCODE
}
