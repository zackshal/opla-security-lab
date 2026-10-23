#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
ATTACKER_IP="${1:?}"; VICTIM_IP="${2:?}"
# Ограниченный поток проще сравнивать между запусками, чем --flood.
echo 'До нагрузки:'
ssh_vm "$VICTIM_IP" 'sudo python3 /tmp/xdp-build/collect.py'
echo 'Отправляем 2000 SYN на HTTP-порт, интервал 1 мс'
ssh_vm "$ATTACKER_IP" "sudo hping3 -n -S -p 80 -i u1000 -c 2000 $VICTIM_IP"
echo 'После нагрузки:'
ssh_vm "$VICTIM_IP" 'sudo python3 /tmp/xdp-build/collect.py'
# hping3 может возвращать ненулевой код при отсутствии ответов; ошибка не скрывается.
