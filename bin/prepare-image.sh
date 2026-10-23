#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../images"
command -v virt-customize >/dev/null || { echo 'Установите libguestfs-tools' >&2; exit 1; }
[[ -f debian-12-base.qcow2 ]] || { echo 'Сначала make bootstrap' >&2; exit 1; }
[[ ! -e debian-12-xdp.qcow2 ]] || { echo 'Образ уже существует; не изменяем используемый backing file' >&2; exit 1; }
# Подготовка с доступом к сети выполняется до запуска изолированной лабораторной.
cp --reflink=auto debian-12-base.qcow2 debian-12-xdp.qcow2.part
trap 'rm -f debian-12-xdp.qcow2.part' ERR
virt-customize -a debian-12-xdp.qcow2.part --network \
    --install clang,llvm,libbpf-dev,linux-libc-dev,bpftool,iproute2,python3,nginx,hping3,curl,tcpdump,cloud-init,openssh-server,gcc,make \
    --run-command 'dpkg-query -W > /etc/opla-packages.txt' \
    --run-command 'cloud-init clean --logs'
mv debian-12-xdp.qcow2.part debian-12-xdp.qcow2
sha256sum debian-12-xdp.qcow2 > prepared.sha256
