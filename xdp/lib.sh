#!/usr/bin/env bash
# Общие SSH-настройки для скриптов стенда.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS=(-i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=5
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$LAB_DIR/known_hosts")
ssh_vm() { local ip="$1"; shift; ssh "${SSH_OPTS[@]}" "student@$ip" "$@"; }
scp_vm() { local ip="$1" dst="$2"; shift 2; scp "${SSH_OPTS[@]}" "$@" "student@$ip:$dst"; }
get_victim_ip() { python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" VICTIM_IP; }
