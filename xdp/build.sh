#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

VICTIM_IP="${1:-$(get_victim_ip)}"
[[ -n "$VICTIM_IP" ]] || { echo "Usage: $0 <victim_ip>"; exit 1; }

echo "[+] build на victim (clang)..."
ssh_vm "$VICTIM_IP" "cd /tmp/xdp-build && make clean && make CC=clang && ls -la *.o && file *.o"
