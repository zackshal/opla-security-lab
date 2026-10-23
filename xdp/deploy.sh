#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

VICTIM_IP="${1:-$(get_victim_ip)}"
[[ -n "$VICTIM_IP" ]] || { echo "Usage: $0 <victim_ip>"; exit 1; }

echo "[+] deploy → ${VICTIM_IP}:/tmp/xdp-build"
ssh_vm "$VICTIM_IP" "mkdir -p /tmp/xdp-build"
scp_vm "$VICTIM_IP" /tmp/xdp-build/ \
    "$(dirname "$0")/xdp_ddos_protect.c" \
    "$(dirname "$0")/Makefile"
echo "✅ deploy OK"
