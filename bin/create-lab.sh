#!/usr/bin/env bash
set -euo pipefail

# Домашняя директория вызывающего пользователя (sudo → не /root)
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    USER_HOME="$HOME"
fi


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

source "${SCRIPT_DIR}/lib.sh"

POOL="${PROJECT_DIR}/images"
CLOUD_INIT_DIR="${PROJECT_DIR}/cloud-init"
TPL_DIR="${PROJECT_DIR}/lib"
LAB_ID="lab-$(date +%s)-$$"
LAB_DIR="/tmp/${LAB_ID}"

log() { echo -e "\033[1;34m[+]\033[0m $*"; }
die() { echo -e "\033[1;31m[✗]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Запускать через sudo"
[[ -d "$TPL_DIR" ]] || die "Нет директории $TPL_DIR"

# ---------- 0. Проверка образов и ключа ----------
for f in debian-12-base.qcow2 alpine-base.qcow2; do
    [[ -f "${POOL}/${f}" ]] || die "Нет ${POOL}/${f}. Запустите ./bootstrap.sh"
done

SSH_PUB="$(cat "${USER_HOME}/.ssh/id_ed25519.pub" 2>/dev/null || cat "${USER_HOME}/.ssh/id_rsa.pub" 2>/dev/null || true)"
[[ -n "$SSH_PUB" ]] || die "Нет ~/.ssh/id_ed25519.pub или ~/.ssh/id_rsa.pub"

# ---------- 1. Мост и подсеть ----------
BRIDGE=$(find_free_bridge)
BASE=$(find_free_subnet) || die "Нет свободных /29 в 100.64.0.0/10"
# BASE = 100.64.0.0 (сетевой адрес /29) — вычисляем .1–.6
NET3="$(echo "$BASE" | awk -F. '{print $1"."$2"."$3}')"
NET4="$(echo "$BASE" | awk -F. '{print $4}')"
GW="${NET3}.$((NET4 + 1))"
ATTACKER_IP="${NET3}.$((NET4 + 2))"
VICTIM_IP="${NET3}.$((NET4 + 3))"
CLIENT_IP="${NET3}.$((NET4 + 4))"
RESERVE_6="${NET3}.$((NET4 + 6))"

# BASE = 100.64.0.0 (сетевой адрес /29)
MASK="255.255.255.248"

log "LAB_ID=${LAB_ID}"
log "BRIDGE=${BRIDGE}  SUBNET=${BASE}/29"
log "GW=${GW}  attacker=${ATTACKER_IP}  victim=${VICTIM_IP}  client=${CLIENT_IP}"

# ---------- 2. Директория лабы ----------
mkdir -p "${LAB_DIR}"

# ---------- 3. Мост ----------
ip link add name "$BRIDGE" type bridge
ip addr add "${GW}/29" dev "$BRIDGE"
ip link set "$BRIDGE" up
log "Мост ${BRIDGE} создан"

# ---------- 4. dnsmasq ----------
sed -e "s|__BRIDGE__|${BRIDGE}|g" \
    -e "s|__GW__|${GW}|g" \
    -e "s|__ATTACKER_IP__|${ATTACKER_IP}|g" \
    -e "s|__VICTIM_IP__|${VICTIM_IP}|g" \
    -e "s|__CLIENT_IP__|${CLIENT_IP}|g" \
    -e "s|__RESERVE_6__|${RESERVE_6}|g" \
    -e "s|__MASK__|${MASK}|g" \
    -e "s|__LAB_DIR__|${LAB_DIR}|g" \
    "${TPL_DIR}/dnsmasq.conf.tpl" > "${LAB_DIR}/dnsmasq.conf"

dnsmasq --conf-file="${LAB_DIR}/dnsmasq.conf"
log "dnsmasq pid=$(cat ${LAB_DIR}/dnsmasq.pid 2>/dev/null || echo '?')"

# ---------- 5. qemu-ifup / ifdown ----------
sed "s|__BRIDGE__|${BRIDGE}|g" "${TPL_DIR}/qemu-ifup.tpl"   > "${LAB_DIR}/qemu-ifup"
sed "s|__BRIDGE__|${BRIDGE}|g" "${TPL_DIR}/qemu-ifdown.tpl" > "${LAB_DIR}/qemu-ifdown"
chmod +x "${LAB_DIR}/qemu-ifup" "${LAB_DIR}/qemu-ifdown"

# ---------- 6. Функция создания ВМ ----------
create_vm() {
    local name="$1" base_img="$2" mem="$3" vcpu="$4" mac="$5" ip="$6"
    local disk="${POOL}/${LAB_ID}-${name}.qcow2"
    local dir="${LAB_DIR}/${name}"
    mkdir -p "$dir"

    qemu-img create -f qcow2 -F qcow2 -b "${POOL}/${base_img}" "$disk" 10G

    sed -e "s|__SSH_KEY__|${SSH_PUB}|g" \
        -e "s|__GW__|${GW}|g" \
        -e "s|__IP__|${ip}|g" \
        "${CLOUD_INIT_DIR}/${name}.yaml" > "${dir}/user-data"

    cat > "${dir}/meta-data" <<META
instance-id: ${LAB_ID}-${name}
local-hostname: ${name}
META

    cloud-localds "${dir}/seed.iso" "${dir}/user-data" "${dir}/meta-data"

    qemu-system-x86_64 \
        -name "${LAB_ID}-${name}" \
        -m "$mem" -smp "$vcpu" \
        -drive file="$disk",if=virtio,cache=writeback \
        -drive file="${dir}/seed.iso",media=cdrom \
        -netdev tap,id=net0,script="${LAB_DIR}/qemu-ifup",downscript="${LAB_DIR}/qemu-ifdown" \
        -device virtio-net-pci,netdev=net0,mac="$mac" \
        -chardev socket,id=con0,path="${LAB_DIR}/${name}-console.sock",server=on,wait=off \
        -serial chardev:con0 \
        -pidfile "${LAB_DIR}/${name}.pid" \
        -nographic -daemonize

    log "VM ${name} pid=$(cat ${LAB_DIR}/${name}.pid)"
}

create_vm attacker debian-12-base.qcow2 1024 1 "52:54:00:00:00:02" "$ATTACKER_IP"
create_vm victim   debian-12-base.qcow2 2048 2 "52:54:00:00:00:03" "$VICTIM_IP"
create_vm client   alpine-base.qcow2      256 1 "52:54:00:00:00:04" "$CLIENT_IP"

# ---------- 7. state.env ----------
cat > "${LAB_DIR}/state.env" <<STATE
LAB_ID=${LAB_ID}
BRIDGE=${BRIDGE}
SUBNET=${BASE}/29
GW=${GW}
ATTACKER_IP=${ATTACKER_IP}
VICTIM_IP=${VICTIM_IP}
CLIENT_IP=${CLIENT_IP}
STATE

# ---------- 8. Итог ----------
echo
log "✅ Стенд готов: ${LAB_DIR}"
echo
echo "SSH (через 20–40 сек после boot):"
echo "  ssh -i ~/.ssh/id_ed25519 student@${VICTIM_IP}"
echo "  ssh -i ~/.ssh/id_ed25519 student@${ATTACKER_IP}"
echo "  ssh -i ~/.ssh/id_ed25519 student@${CLIENT_IP}"
echo
echo "Или через обёртку:"
echo "  ./bin/ssh.sh ${LAB_DIR} victim"
echo
echo "Serial-консоль:"
echo "  socat unix-connect:${LAB_DIR}/victim-console.sock stdio"
echo
echo "Остановка:"
echo "  sudo ./bin/cleanup-lab.sh ${LAB_DIR}"
