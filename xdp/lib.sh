#!/usr/bin/env bash
# Общие функции для XDP-скриптов.
# SSH-опции — МАССИВ, а не строка: избегаем бага "-i строка целиком".

SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS=(
    -i "$SSH_KEY"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o ConnectTimeout=5
)

# ssh_vm <ip> [команда...]
ssh_vm() {
    local ip="$1"; shift
    ssh "${SSH_OPTS[@]}" "student@${ip}" "$@"
}

# scp_vm <src...> <dst>: копирует на student@<ip>:<dst>
# использование: scp_vm <ip> <dst> <src...>
scp_vm() {
    local ip="$1" dst="$2"; shift 2
    scp "${SSH_OPTS[@]}" "$@" "student@${ip}:${dst}"
}

# victim_ip из state.env (fallback: аргумент)
get_victim_ip() {
    local lab="${1:-$(ls -dt /tmp/lab-*/ 2>/dev/null | head -1)}"
    grep VICTIM_IP "${lab%/}/state.env" 2>/dev/null | cut -d= -f2
}
