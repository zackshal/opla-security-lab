#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

VICTIM_IP="${1:-$(get_victim_ip)}"
[[ -n "$VICTIM_IP" ]] || { echo "Usage: $0 <victim_ip>"; exit 1; }

echo "[+] load XDP на ens3 (native → fallback generic)"
ssh_vm "$VICTIM_IP" "sudo ip link set dev ens3 xdp off 2>/dev/null || true; \
    sudo ip link set dev ens3 xdp obj /tmp/xdp-build/xdp_ddos_protect.o sec xdp 2>/dev/null || \
    sudo ip link set dev ens3 xdp obj /tmp/xdp-build/xdp_ddos_protect.o sec xdp generic"

echo "[+] проверка:"
ssh_vm "$VICTIM_IP" "ip link show ens3 | grep -oE 'xdp[a-z]*' || echo 'native'; \
    sudo bpftool prog list | grep -A1 xdp_ddos_protect; \
    sudo bpftool map list | grep -E 'rate_limit|first_seen' || true"
