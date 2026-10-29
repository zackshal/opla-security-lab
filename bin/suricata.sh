#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/xdp/lib.sh"
mode="${1:?ids|ips|off|status}"
case "$mode" in ids|ips|off|status) ;; *) exit 2;; esac
ip="$(get_victim_ip)"
subnet="$(python3 "$ROOT/bin/state.py" "$LAB_DIR" SUBNET)"
if ! ssh_vm "$ip" 'command -v suricata >/dev/null'; then
  echo 'BLOCKED: Suricata is missing from the victim VM; use a victim role image prepared with make image ROLE=victim.' >&2
  exit 2
fi
if ! ssh_vm "$ip" 'python3 -c "import yaml"'; then
  echo 'BLOCKED: PyYAML is missing from the victim VM; use a victim role image prepared with make image ROLE=victim.' >&2
  exit 2
fi
ssh_vm "$ip" 'mkdir -p /tmp/opla-suricata'
scp_vm "$ip" /tmp/opla-suricata/ "$ROOT/security/suricata/manage.py" "$ROOT/security/suricata/nft_policy.py" "$ROOT/security/suricata/opla.rules" "$ROOT/security/suricata/ips.rules" "$ROOT/security/suricata/runtime.py"
extra=""
[[ "${SURICATA_ET_OPEN:-0}" != 1 ]] || extra="--et-open"
if [[ "$mode" == ids || "$mode" == ips ]]; then
  scp_vm "$ip" /tmp/opla-suricata/ "$ROOT/security/logrotate/opla-suricata" "$ROOT/security/logrotate/opla-nginx"
  ssh_vm "$ip" 'sudo install -m 644 /tmp/opla-suricata/opla-suricata /etc/logrotate.d/opla-suricata && sudo install -m 644 /tmp/opla-suricata/opla-nginx /etc/logrotate.d/opla-nginx'
fi
ssh_vm "$ip" "sudo python3 /tmp/opla-suricata/manage.py '$mode' --subnet '$subnet' $extra"
