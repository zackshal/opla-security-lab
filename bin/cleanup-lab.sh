#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
POOL="${PROJECT_DIR}/images"

LAB_DIR="${1:-}"
[[ -n "$LAB_DIR" && -d "$LAB_DIR" ]] || { echo "Usage: $0 <lab-dir>"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "Запускать через sudo"; exit 1; }
[[ -f "${LAB_DIR}/state.env" ]] || { echo "Нет ${LAB_DIR}/state.env"; exit 1; }

# shellcheck disable=SC1091
source "${LAB_DIR}/state.env"

echo "[+] Останавливаю ВМ..."
for unit in $(systemctl list-units --plain --no-legend "qemu-${LAB_ID}-*" 2>/dev/null | awk "{print \$1}"); do
    systemctl stop "$unit" 2>/dev/null || true
done
sleep 2
sleep 2

echo "[+] Останавливаю dnsmasq..."
[[ -f "${LAB_DIR}/dnsmasq.pid" ]] && kill "$(cat "${LAB_DIR}/dnsmasq.pid")" 2>/dev/null || true

echo "[+] Удаляю мост ${BRIDGE}..."
ip link del "${BRIDGE}" 2>/dev/null || true

echo "[+] Удаляю overlay-диски..."
rm -f "${POOL}/${LAB_ID}-"*.qcow2

echo "[+] Удаляю ${LAB_DIR}..."
rm -rf "${LAB_DIR}"

echo "[+] Готово."
