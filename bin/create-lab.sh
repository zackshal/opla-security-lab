#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/lib.sh"
[[ $EUID == 0 ]] || { echo 'Запускайте через make up' >&2; exit 1; }
for cmd in qemu-system-x86_64 qemu-img cloud-localds dnsmasq ip nft flock python3 systemd-run; do
    command -v "$cmd" >/dev/null || { echo "Не найден $cmd" >&2; exit 1; }
done
[[ -c /dev/kvm ]] || { echo 'Нужен доступный KVM (/dev/kvm)' >&2; exit 1; }
[[ -f "$PROJECT_DIR/images/debian-12-xdp.qcow2" ]] || { echo 'Сначала make image' >&2; exit 1; }
install -d -m 755 /run/opla
exec 9>/run/opla/create.lock
flock -n 9 || { echo 'Другой процесс создаёт стенд' >&2; exit 1; }
CALLER="${SUDO_USER:-root}"
CALLER_HOME="$(getent passwd "$CALLER" | cut -d: -f6)"
SSH_PUB="$(cat "${SSH_KEY_PUB:-$CALLER_HOME/.ssh/id_ed25519.pub}")"
[[ "$SSH_PUB" == ssh-* ]] || { echo 'Нужен SSH public key' >&2; exit 1; }
LAB_DIR="$(mktemp -d /run/opla/lab-XXXXXXXX)"
chmod 755 "$LAB_DIR"
LAB_ID="${LAB_DIR##*/}"
BRIDGE="$(find_free_bridge)"
BASE="$(find_free_subnet)"
NET3="${BASE%.*}"; NET4="${BASE##*.}"
GW="$NET3.$((NET4+1))"; ATTACKER_IP="$NET3.$((NET4+2))"
VICTIM_IP="$NET3.$((NET4+3))"; CLIENT_IP="$NET3.$((NET4+4))"
cat > "$LAB_DIR/state.env" <<STATE
LAB_ID=$LAB_ID
BRIDGE=$BRIDGE
SUBNET=$BASE/29
GW=$GW
ATTACKER_IP=$ATTACKER_IP
VICTIM_IP=$VICTIM_IP
CLIENT_IP=$CLIENT_IP
STATE
install -m 600 -o "$CALLER" /dev/null "$LAB_DIR/known_hosts"
# После неудачного запуска убираем только ресурсы этого экземпляра.
trap 'code=$?; "$SCRIPT_DIR/cleanup-lab.sh" "$LAB_DIR" || true; exit "$code"' ERR
ip link add "$BRIDGE" type bridge
ip addr add "$GW/29" dev "$BRIDGE"
ip link set "$BRIDGE" up
TABLE="opla_${LAB_ID//-/_}"
# Разрешаем связь ВМ друг с другом, но запрещаем маршрутизацию через хост.
nft -f - <<NFT
add table inet $TABLE
add chain inet $TABLE forward { type filter hook forward priority -20; policy accept; }
add rule inet $TABLE forward iifname "$BRIDGE" oifname != "$BRIDGE" drop
add rule inet $TABLE forward oifname "$BRIDGE" iifname != "$BRIDGE" drop
add chain inet $TABLE input { type filter hook input priority -20; policy accept; }
add rule inet $TABLE input iifname "$BRIDGE" ct state established,related accept
add rule inet $TABLE input iifname "$BRIDGE" udp dport 67 accept
add rule inet $TABLE input iifname "$BRIDGE" drop
NFT
cat > "$LAB_DIR/dnsmasq.conf" <<CONF
port=0
interface=$BRIDGE
bind-interfaces
dhcp-range=$ATTACKER_IP,$CLIENT_IP,255.255.255.248,12h
dhcp-option=3
dhcp-option=6
dhcp-host=52:54:00:00:00:02,$ATTACKER_IP
dhcp-host=52:54:00:00:00:03,$VICTIM_IP
dhcp-host=52:54:00:00:00:04,$CLIENT_IP
pid-file=$LAB_DIR/dnsmasq.pid
log-facility=$LAB_DIR/dnsmasq.log
CONF
# systemd хранит PID демона; cleanup не доверяет произвольному pid-файлу.
systemd-run --quiet --collect --unit="dhcp-$LAB_ID" dnsmasq --keep-in-foreground --conf-file="$LAB_DIR/dnsmasq.conf"
create_vm() {
    local name="$1" mem="$2" cpus="$3" mac="$4" addr="$5" tap="$6"
    local dir="$LAB_DIR/$name"
    mkdir "$dir"
    qemu-img create -q -f qcow2 -F qcow2 -b "$PROJECT_DIR/images/debian-12-xdp.qcow2" "$dir/disk.qcow2"
    # JSON-строка корректно экранирует ключ при подстановке в YAML.
    python3 - "$PROJECT_DIR/cloud-init/$name.yaml" "$dir/user-data" "$SSH_PUB" <<'PYCODE'
import json,sys
from pathlib import Path
Path(sys.argv[2]).write_text(Path(sys.argv[1]).read_text().replace('__SSH_KEY__',json.dumps(sys.argv[3])))
PYCODE
    printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$LAB_ID" "$name" "$name" > "$dir/meta-data"
    cat > "$dir/network-config" <<NET
version: 2
ethernets:
  lab:
    match: {macaddress: "$mac"}
    set-name: ens3
    addresses: [$addr/29]
    dhcp4: false
    dhcp6: false
    accept-ra: false
NET
    cloud-localds --network-config="$dir/network-config" "$dir/seed.iso" "$dir/user-data" "$dir/meta-data"
    ip tuntap add dev "$tap" mode tap
    ip link set "$tap" master "$BRIDGE"
    ip link set "$tap" up
    systemd-run --quiet --collect --unit="qemu-$LAB_ID-$name" \
        qemu-system-x86_64 -enable-kvm -cpu host -m "$mem" -smp "$cpus" \
        -drive "file=$dir/disk.qcow2,if=virtio" -drive "file=$dir/seed.iso,media=cdrom" \
        -netdev "tap,id=n0,ifname=$tap,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n0,mac=$mac" \
        -chardev "socket,id=c0,path=$LAB_DIR/$name-console.sock,server=on,wait=off" \
        -serial chardev:c0 -display none -monitor none -no-reboot
    for ((i=0;i<100;i++)); do
        [[ -S "$LAB_DIR/$name-console.sock" ]] && break
        systemctl is-active --quiet "qemu-$LAB_ID-$name" || return 1
        sleep .1
    done
    [[ -S "$LAB_DIR/$name-console.sock" ]]
    chown "$CALLER" "$LAB_DIR/$name-console.sock"
}
N="${BRIDGE#br-op}"
create_vm attacker 1024 1 52:54:00:00:00:02 "$ATTACKER_IP" "op${N}a"
create_vm victim 2048 2 52:54:00:00:00:03 "$VICTIM_IP" "op${N}v"
create_vm client 512 1 52:54:00:00:00:04 "$CLIENT_IP" "op${N}c"
trap - ERR
echo "Стенд запущен: $LAB_DIR"
echo "Victim: $VICTIM_IP; attacker: $ATTACKER_IP; client: $CLIENT_IP"
echo 'Дождитесь cloud-init: make ready. При нескольких стендах указывайте LAB_DIR.'
