#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
VICTIM_IP="${1:-$(get_victim_ip)}"
THRESHOLD="${THRESHOLD:-100}"
[[ "$THRESHOLD" =~ ^[1-9][0-9]{0,6}$ ]] || { echo 'Некорректный THRESHOLD' >&2; exit 1; }
MAX_SOURCES="${MAX_SOURCES:-4096}"
[[ "$MAX_SOURCES" =~ ^[1-9][0-9]{0,4}$ ]] && ((MAX_SOURCES<=65536)) || exit 2
ssh_vm "$VICTIM_IP" "cd /tmp/xdp-build && make clean && make THRESHOLD=$THRESHOLD MAX_SOURCES=$MAX_SOURCES"
