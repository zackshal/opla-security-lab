#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
VICTIM_IP="${1:-$(get_victim_ip)}"
ssh_vm "$VICTIM_IP" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
if [ -e /sys/fs/bpf/opla/program ]; then
    own=$(bpftool -j prog show pinned /sys/fs/bpf/opla/program | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d[0] if isinstance(d,list) else d)["id"])')
    current=$(ip -j link show dev ens3 | python3 -c 'import json,sys; d=json.load(sys.stdin)[0].get("xdp",{}); print(d.get("prog",{}).get("id",d.get("prog_id",0)))')
    if [ "$current" != 0 ] && [ "$current" != "$own" ]; then
        echo 'На ens3 чужая XDP-программа; выгрузка отменена' >&2; exit 1
    fi
    ip link set dev ens3 xdp off
fi
rm -f /sys/fs/bpf/opla/program /sys/fs/bpf/opla/maps/syn_windows /sys/fs/bpf/opla/maps/xdp_stats
REMOTE
