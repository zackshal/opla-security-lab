#!/usr/bin/env bash
# Общие SSH-настройки для скриптов стенда.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="${LAB_DIR:-}"
[[ -n "$LAB_DIR" ]] || {
    echo "BLOCKED: LAB_DIR обязателен; выберите лабораторию явно" >&2
    return 2
}
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS=(-i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=5
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$LAB_DIR/known_hosts")
ssh_vm() {
    local ip="$1"; shift
    ip="$(python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" SSH_IP "$ip")"
    ssh "${SSH_OPTS[@]}" "student@$ip" "$@"
}
scp_vm() { local ip="$1" dst="$2"; shift 2; scp "${SSH_OPTS[@]}" "$@" "student@$ip:$dst"; }
get_victim_ip() { python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" VICTIM_IP; }

wait_vm_ready() {
    local ip="$1" vm="$2" deadline=$((SECONDS + 300)) remaining output code
    ip="$(python3 "$PROJECT_DIR/bin/state.py" "$LAB_DIR" SSH_IP "$ip")" || return
    echo "Ожидание $vm ($ip): SSH и cloud-init, не более 300 секунд..."
    while (( SECONDS < deadline )); do
        remaining=$((deadline - SECONDS))
        if output=$(timeout "$remaining" ssh "${SSH_OPTS[@]}" \
            -o ServerAliveInterval=5 -o ServerAliveCountMax=3 "student@$ip" \
            'sudo -n timeout 240 cloud-init status --wait' 2>&1); then
            printf '%s\n' "$output"
            echo "PASS: $vm — SSH доступен, cloud-init завершён"
            return 0
        else
            code=$?
        fi
        # Retry transport startup only; never hide authentication/host-key failures.
        if [[ "$code" == 255 && "$output" =~ (Connection\ refused|Connection\ timed\ out|No\ route\ to\ host|Network\ is\ unreachable) ]]; then
            (( SECONDS + 2 < deadline )) || break
            sleep 2
            continue
        fi
        printf '%s\n' "$output" >&2
        echo "BLOCKED: $vm — проверка готовности завершилась с кодом $code" >&2
        return "$code"
    done
    echo "BLOCKED: $vm ($ip) — истекло время ожидания 300 секунд" >&2
    return 124
}
