#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES="${SCRIPT_DIR}/images"
mkdir -p "$IMAGES"

declare -A URLS=(
    ["debian-12-base.qcow2"]="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
    ["alpine-base.qcow2"]="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-bios-cloudinit-r0.qcow2"
)

for name in "${!URLS[@]}"; do
    dst="${IMAGES}/${name}"
    if [[ -f "$dst" ]]; then
        echo "[=] $name уже есть"
        continue
    fi
    echo "[+] Скачиваю $name..."
    curl -fL --progress-bar -o "$dst.part" "${URLS[$name]}"
    mv "$dst.part" "$dst"
done

if [[ -f "${SCRIPT_DIR}/checksums.sha256" ]]; then
    echo "[+] Проверяю контрольные суммы..."
    (cd "$IMAGES" && sha256sum -c "${SCRIPT_DIR}/checksums.sha256")
fi

echo "✅ Образы готовы"
