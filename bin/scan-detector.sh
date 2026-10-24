#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/xdp/lib.sh"
action="${1:-status}"
case "$action" in start|status|off) ;; *) echo 'start|status|off'; exit 2;; esac
victim_ip="$(get_victim_ip)"
ssh_vm "$victim_ip" 'mkdir -p /tmp/opla-scan'
scp_vm "$victim_ip" /tmp/opla-scan/ "$ROOT/security/scan/detector.py" "$ROOT/security/scan/install.py"
ssh_vm "$victim_ip" "sudo python3 /tmp/opla-scan/install.py '$action' --target '$victim_ip'"
