#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="${LAB_DIR:-$(python3 "$PROJECT_DIR/bin/state.py" --latest)}"
export LAB_DIR
[[ -n "$LAB_DIR" ]] || { echo 'Нет активного стенда: make up' >&2; exit 1; }
ACTION="${1:?}"; shift
VICTIM_IP="$(python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" VICTIM_IP)"
source "$PROJECT_DIR/xdp/lib.sh"
case "$ACTION" in
    ssh) VM="${1:-victim}"; case "$VM" in
        victim|attacker|client) IP="$(python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" "${VM^^}_IP")";;
        *) echo 'VM=attacker|victim|client' >&2; exit 1;; esac
        ssh_vm "$IP" ;;
    ready) for VM in attacker victim client; do
        IP="$(python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" "${VM^^}_IP")"
        ssh_vm "$IP" 'sudo cloud-init status --wait' || exit 1
        done ;;
    console) exec "$PROJECT_DIR/bin/console.sh" "$LAB_DIR" "${1:-victim}" ;;
    down) systemctl --user stop "opla-monitor-${LAB_DIR##*/}.service" 2>/dev/null || true
        exec sudo "$PROJECT_DIR/bin/cleanup-lab.sh" "$LAB_DIR" ;;
    dashboard) exec python3 "$PROJECT_DIR/xdp/dashboard.py" "$VICTIM_IP" ;;
    collect) ssh_vm "$VICTIM_IP" 'sudo python3 /tmp/xdp-build/collect.py' ;;
    test) ATTACKER_IP="$(python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" ATTACKER_IP)"
        exec "$PROJECT_DIR/xdp/test.sh" "$ATTACKER_IP" "$VICTIM_IP" ;;
    deploy|build|load|unload) exec "$PROJECT_DIR/xdp/$ACTION.sh" "$VICTIM_IP" ;;
    *) echo 'Неизвестное действие' >&2; exit 1;;
esac
