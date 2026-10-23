#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Нужен sudo' >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="${1:?Укажите каталог стенда}"
# Проверка пути и владельца предшествует любому удалению.
LAB_ID="$(python3 "$SCRIPT_DIR/state.py" "$LAB_DIR" LAB_ID)"
BRIDGE="$(python3 "$SCRIPT_DIR/state.py" "$LAB_DIR" BRIDGE)"
for name in attacker victim client; do
    systemctl stop "qemu-$LAB_ID-$name.service" 2>/dev/null || true
done
systemctl stop "dhcp-$LAB_ID.service" 2>/dev/null || true
for suffix in a v c; do ip link del "op${BRIDGE#br-op}$suffix" 2>/dev/null || true; done
ip link del "$BRIDGE" 2>/dev/null || true
nft delete table inet "opla_${LAB_ID//-/_}" 2>/dev/null || true
rm -rf -- "${LAB_DIR:?}"
echo "Стенд $LAB_ID остановлен"
