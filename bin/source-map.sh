#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/xdp/lib.sh"
ip="$(get_victim_ip)"
scp_vm "$ip" /tmp/opla-source-map.py "$ROOT/bin/source-map.py"
ssh_vm "$ip" 'sudo python3 /tmp/opla-source-map.py'
