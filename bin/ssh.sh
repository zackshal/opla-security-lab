#!/usr/bin/env bash
# Usage: ssh.sh <lab-dir> <attacker|victim|client>
set -euo pipefail

LAB_DIR="${1:-}"
VM="${2:-}"

[[ -n "$LAB_DIR" && -d "$LAB_DIR" ]] || { echo "Usage: $0 <lab-dir> <vm>"; exit 1; }
[[ -f "${LAB_DIR}/state.env" ]] || { echo "Нет state.env в $LAB_DIR"; exit 1; }

# shellcheck disable=SC1091
source "${LAB_DIR}/state.env"

case "$VM" in
    attacker) IP="$ATTACKER_IP" ;;
    victim)   IP="$VICTIM_IP" ;;
    client)   IP="$CLIENT_IP" ;;
    *) echo "Неизвестная ВМ: $VM (attacker|victim|client)"; exit 1 ;;
esac

exec ssh -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null \
         -o LogLevel=ERROR \
         -o ConnectTimeout=5 \
         -i ~/.ssh/id_ed25519 "student@${IP}"
