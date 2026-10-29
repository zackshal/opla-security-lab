#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
VICTIM_IP="${1:-$(get_victim_ip)}"
ssh_vm "$VICTIM_IP" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
lock_path=/run/lock/opla-xdp.lock
if [[ ! -e "$lock_path" && ! -L "$lock_path" ]]; then
    (umask 077; set -C; : > "$lock_path") 2>/dev/null || true
fi
[[ -d /run/lock && ! -L /run/lock && -f "$lock_path" && ! -L "$lock_path" ]] || {
    echo 'BLOCKED: unsafe or unavailable XDP lifecycle lock path' >&2; exit 2;
}
read -r lock_dir_uid lock_dir_mode < <(stat -c '%u %a' /run/lock)
read -r lock_uid lock_links lock_mode < <(stat -c '%u %h %a' "$lock_path")
(( lock_dir_uid == 0 && ((8#$lock_dir_mode & 18) == 0
   || ((8#$lock_dir_mode & 512) != 0 && (8#$lock_dir_mode & 2) != 0)) && lock_uid == 0
   && lock_links == 1 && (8#$lock_mode & 18) == 0 )) || {
    echo 'BLOCKED: XDP lifecycle lock ownership or permissions are unsafe' >&2; exit 2;
}
exec 9<>"$lock_path"
flock -n 9 || { echo 'BLOCKED: another OPLA XDP lifecycle operation is active' >&2; exit 2; }
state=$(python3 /tmp/xdp-build/runtime-guard.py unload-check)
if [ "$state" = attached-owned ]; then
    ip link set dev ens3 xdp off
fi
state=$(python3 /tmp/xdp-build/runtime-guard.py unload-check)
case "$state" in
    pinned-unattached)
        rm -f /sys/fs/bpf/opla/program \
            /sys/fs/bpf/opla/maps/syn_windows \
            /sys/fs/bpf/opla/maps/xdp_stats \
            /sys/fs/bpf/opla/maps/xdp_policy
        rmdir /sys/fs/bpf/opla/maps
        rmdir /sys/fs/bpf/opla
        rm -f /tmp/xdp-build/load-receipt.json
        ;;
    already-unloaded)
        echo 'XDP и OPLA pins отсутствуют; нечего очищать.'
        ;;
    *)
        echo "Неожиданное состояние XDP: $state; ресурсы сохранены." >&2
        exit 2
        ;;
esac
REMOTE
