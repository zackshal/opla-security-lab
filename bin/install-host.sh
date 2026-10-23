#!/usr/bin/env bash
# Установка на чистый Debian 12 amd64 по официальному apt-репозиторию Docker.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'sudo ./bin/install-host.sh' >&2; exit 1; }
. /etc/os-release
[[ "$ID" == debian && "$VERSION_ID" == 12 ]] || { echo 'Инструкция рассчитана на Debian 12' >&2; exit 1; }
apt-get update
apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils dnsmasq-base \
    iproute2 nftables libguestfs-tools socat openssh-client curl ca-certificates \
    python3 python3-yaml build-essential git
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<REPO
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
REPO
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
echo 'Для обычного пользователя настройте группу docker, затем перезайдите в сессию.'
