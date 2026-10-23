#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

ATTACKER_IP="${1:-}"; VICTIM_IP="${2:-}"
[[ -n "$ATTACKER_IP" && -n "$VICTIM_IP" ]] || { echo "Usage: $0 <attacker_ip> <victim_ip>"; exit 1; }

echo "=== ДО атаки ==="
ssh_vm "$VICTIM_IP" "sudo bpftool map dump name rate_limit_map 2>/dev/null || echo '(пусто)'"

echo
echo "=== SYN-флуд 10 сек: ${ATTACKER_IP} → ${VICTIM_IP} ==="
ssh_vm "$ATTACKER_IP" "sudo timeout 10 hping3 -S --flood -p 80 ${VICTIM_IP} || true"

echo
echo "=== ПОСЛЕ атаки ==="
ssh_vm "$VICTIM_IP" "sudo bpftool map dump name rate_limit_map 2>/dev/null || echo '(пусто)'"

echo
echo "=== trace_pipe (XDP-логи) ==="
ssh_vm "$VICTIM_IP" "sudo timeout 2 cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | grep XDP | tail -5 || echo '(пусто)'"
