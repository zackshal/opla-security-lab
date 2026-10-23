#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
{ date -Is; uname -a; qemu-system-x86_64 --version; nft --version; python3 --version;
  dpkg-query -W qemu-system-x86 dnsmasq cloud-image-utils libguestfs-tools 2>/dev/null || true;
  cat images/*.sha256 2>/dev/null || true;
  docker compose -f monitoring/compose.yaml images 2>/dev/null || true;
} > reports/versions-host.txt
LAB_DIR="${LAB_DIR:-$(python3 bin/state.py --latest)}"; export LAB_DIR
source xdp/lib.sh
ssh_vm "$(get_victim_ip)" 'uname -a; dpkg-query -W; clang --version; bpftool version' > reports/versions-victim.txt
echo 'Версии сохранены в reports/'
