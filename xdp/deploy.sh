#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
VICTIM_IP="${1:-$(get_victim_ip)}"
ssh_vm "$VICTIM_IP" 'mkdir -p /tmp/xdp-build'
scp_vm "$VICTIM_IP" /tmp/xdp-build/ "$PROJECT_DIR/xdp/xdp_ddos_protect.c" "$PROJECT_DIR/xdp/Makefile" "$PROJECT_DIR/xdp/collect.py"
echo 'Исходники и сборщик метрик скопированы'
