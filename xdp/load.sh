#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
VICTIM_IP="${1:-$(get_victim_ip)}"
# Фиксированный pin-каталог связывает загрузчик и сборщик метрик.
ssh_vm "$VICTIM_IP" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
ip link show dev ens3 >/dev/null
# Не заменяем неизвестную программу на интерфейсе.
if ip -j link show dev ens3 | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)[0].get("xdp",{}).get("attached","off") != "off" else 1)'; then
    echo 'На ens3 уже есть XDP. Сначала выполните make xdp-unload.' >&2
    exit 1
fi
# Validate the exact build artifact before modifying BPF state.
python3 /tmp/xdp-build/fingerprint.py validate-build >/dev/null
rm -f /tmp/xdp-build/load-receipt.json

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
if [ -e /sys/fs/bpf/opla/program ]; then
    echo 'Остался предыдущий pin-каталог: выполните make xdp-unload' >&2; exit 1
fi
mkdir -p /sys/fs/bpf/opla/maps
bpftool prog load /tmp/xdp-build/xdp_ddos_protect.o /sys/fs/bpf/opla/program type xdp pinmaps /sys/fs/bpf/opla/maps
if ip link set dev ens3 xdpdrv pinned /sys/fs/bpf/opla/program; then
    echo 'XDP: native'
elif ip link set dev ens3 xdpgeneric pinned /sys/fs/bpf/opla/program; then
    echo 'XDP: generic'
else
    rm -f /sys/fs/bpf/opla/program /sys/fs/bpf/opla/maps/*
    exit 1
fi
# Record program identity after successful attachment.
# Failure leaves XDP attached; do not perform unsafe automatic rollback.
python3 /tmp/xdp-build/fingerprint.py record-load

ip -details link show ens3
REMOTE
