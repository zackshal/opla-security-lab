#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
VICTIM_IP="${1:-$(get_victim_ip)}"
# Фиксированный pin-каталог связывает загрузчик и сборщик метрик.
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
ip link show dev ens3 >/dev/null
# Missing, malformed or unknown attachment state blocks before any BPF changes.
python3 /tmp/xdp-build/runtime-guard.py load-check
# Validate the exact build artifact before modifying BPF state.
python3 /tmp/xdp-build/fingerprint.py validate-build >/dev/null
if [ -e /tmp/xdp-build/load-receipt.json ] || [ -L /tmp/xdp-build/load-receipt.json ]; then
    echo 'Остался load receipt; сначала проверьте make xdp-unload.' >&2; exit 1
fi

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
if [ -e /sys/fs/bpf/opla ] || [ -L /sys/fs/bpf/opla ]; then
    echo 'Остался pin-каталог OPLA или чужой ресурс; ручная сверка обязательна' >&2; exit 1
fi
mkdir -p /sys/fs/bpf/opla/maps
bpftool prog load /tmp/xdp-build/xdp_ddos_protect.o /sys/fs/bpf/opla/program type xdp pinmaps /sys/fs/bpf/opla/maps
if ip link set dev ens3 xdpdrv pinned /sys/fs/bpf/opla/program; then
    echo 'XDP: native'
elif ip link set dev ens3 xdpgeneric pinned /sys/fs/bpf/opla/program; then
    echo 'XDP: generic'
else
    echo 'XDP attach failed; BPF pins are preserved for ownership review.' >&2
    exit 1
fi
# Record program identity after successful attachment.
# Failure leaves XDP attached; do not perform unsafe automatic rollback.
python3 /tmp/xdp-build/fingerprint.py record-load

ip -details link show ens3
REMOTE
