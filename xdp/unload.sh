#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

VICTIM_IP="${1:-$(get_victim_ip)}"
[[ -n "$VICTIM_IP" ]] || exit 0

ssh_vm "$VICTIM_IP" "sudo ip link set dev ens3 xdp off 2>/dev/null && echo '✅ XDP выгружен' || echo '(не был загружен)'"
