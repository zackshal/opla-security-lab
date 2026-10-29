#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
ATTACKER_IP="${1:?}"; VICTIM_IP="${2:?}"
# Ограниченный поток проще сравнивать между запусками, чем --flood.
echo 'До нагрузки:'
before="$(ssh_vm "$VICTIM_IP" 'sudo python3 /tmp/xdp-build/collect.py')"
if ! python3 "$PROJECT_DIR/xdp/validate-test-snapshot.py" <<<"$before"; then
    exit 2
fi
printf '%s\n' "$before"
echo 'Отправляем 2000 SYN на HTTP-порт, интервал 1 мс'
result=0
ssh_vm "$ATTACKER_IP" "sudo hping3 -n -S -p 80 -i u1000 -c 2000 $VICTIM_IP" || result=$?
echo 'После нагрузки:'
after="$(ssh_vm "$VICTIM_IP" 'sudo python3 /tmp/xdp-build/collect.py')"
if ! python3 "$PROJECT_DIR/xdp/validate-test-snapshot.py" <<<"$after"; then
    exit 2
fi
printf '%s\n' "$after"
# hping3 может возвращать ненулевой код при отсутствии ответов; ошибка не скрывается.
printf "Код завершения генератора: %s\n" "$result"
exit "$result"
