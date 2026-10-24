#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
role="${1:-victim}"
case "$role" in
  victim) output=debian-12-xdp.qcow2; size=10G
    packages=clang,llvm,libbpf-dev,linux-libc-dev,bpftool,iproute2,python3,python3-yaml,nginx,hping3,curl,tcpdump,cloud-init,openssh-server,gcc,make,suricata,suricata-update,nftables,logrotate ;;
  attacker) output=debian-12-attacker.qcow2; size=4G
    packages=hping3,curl,python3,iproute2,cloud-init,openssh-server ;;
  client) output=debian-12-client.qcow2; size=4G
    packages=curl,python3,iproute2,cloud-init,openssh-server ;;
  *) echo 'role: victim|attacker|client' >&2; exit 2;;
esac
cd "$ROOT/images"
command -v virt-customize >/dev/null
[[ -f debian-12-base.qcow2 ]] || { echo 'Run make bootstrap' >&2; exit 1; }
[[ ! -e "$output" && ! -e "$output.part" ]] || { echo 'Existing image/partial: inspect it; never overwrite an active backing file' >&2; exit 1; }
qemu-img create -f qcow2 "$output.part" "$size"
virt-resize --expand /dev/sda1 debian-12-base.qcow2 "$output.part"
virt-customize -a "$output.part" --network --install "$packages" \
  --run-command 'dpkg-query -W > /etc/opla-packages.txt' \
  --run-command 'apt-get clean' \
  --run-command 'rm -rf /var/lib/apt/lists/*' \
  --run-command 'if command -v suricata >/dev/null; then systemctl disable suricata.service; fi' \
  --run-command 'cloud-init clean --logs'
if [[ "$role" == victim && "${SURICATA_ET_OPEN:-0}" == 1 ]]; then
  virt-customize -a "$output.part" --network --run-command 'suricata-update'
fi
qemu-img check -f qcow2 "$output.part"
mv "$output.part" "$output"
sha256sum "$output" > "$output.sha256"
printf '%s\n' "$role" > "$output.role"
