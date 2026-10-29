#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
VICTIM_IP="${1:-$(get_victim_ip)}"
THRESHOLD="${THRESHOLD:-100}"
[[ "$THRESHOLD" =~ ^[1-9][0-9]{0,6}$ ]] || { echo 'Некорректный THRESHOLD' >&2; exit 1; }
MAX_SOURCES="${MAX_SOURCES:-4096}"
[[ "$MAX_SOURCES" =~ ^[1-9][0-9]{0,4}$ ]] && ((MAX_SOURCES<=65536)) || exit 2
WINDOW_NS="${WINDOW_NS:-1000000000}"
[[ "$WINDOW_NS" =~ ^[1-9][0-9]{0,14}$ ]] || {
    echo 'Некорректный WINDOW_NS' >&2
    exit 2
}

scp_vm "$VICTIM_IP" /tmp/xdp-build/ "$PROJECT_DIR/xdp/fingerprint.py" "$PROJECT_DIR/xdp/runtime-guard.py"

ssh_vm "$VICTIM_IP" "cd /tmp/xdp-build && rm -f build-manifest.json && make clean && make THRESHOLD=$THRESHOLD MAX_SOURCES=$MAX_SOURCES WINDOW_NS=$WINDOW_NS"

ssh_vm "$VICTIM_IP" "python3 /tmp/xdp-build/fingerprint.py build --threshold $THRESHOLD --window-ns $WINDOW_NS --max-sources $MAX_SOURCES"
