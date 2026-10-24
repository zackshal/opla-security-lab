#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../xdp/lib.sh"
policy_mode="${1:-observe}"
case "$policy_mode" in off|observe|block) ;; *) echo 'Expected off, observe or block' >&2; exit 2;; esac
victim_ip="$(get_victim_ip)"
management_ip="$(python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" GW)"
client_ip="$(python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" CLIENT_IP)"
[[ "$management_ip" =~ ^[0-9.]+$ && "$client_ip" =~ ^[0-9.]+$ ]] || exit 2
scp_vm "$victim_ip" /tmp/opla-xdp-scan-policy.py "$PROJECT_DIR/xdp/scan-policy.py"
ssh_vm "$victim_ip" "sudo python3 /tmp/opla-xdp-scan-policy.py --mode $policy_mode --trusted-source $management_ip --trusted-source $client_ip" </dev/null
