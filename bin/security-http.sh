#!/usr/bin/env bash
# Добавляем или убираем только наш файл, с проверкой nginx и откатом при ошибке.
set -euo pipefail
cd "$(dirname "$0")/.."
source xdp/lib.sh
victim_ip="$(get_victim_ip)"
action="${1:-apply}"
case "$action" in apply|remove) ;; *) echo 'bash bin/security-http.sh apply|remove' >&2; exit 2 ;; esac
scp_vm "$victim_ip" /tmp/opla-l7.conf security/nginx/opla-l7.conf
ssh_vm "$victim_ip" "sudo bash -s -- $action" <<'REMOTE'
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
action="$1"
file=/etc/nginx/conf.d/opla-l7.conf
backup="$(mktemp /tmp/opla-nginx-XXXXXXXX)"
had_file=0
if [ -e "$file" ]; then cp -p "$file" "$backup"; had_file=1; fi
restore() {
    if [ "$had_file" = 1 ]; then cp -p "$backup" "$file"; else rm -f "$file"; fi
}
trap 'restore; rm -f "$backup"' ERR
if [ "$action" = apply ]; then
    install -m 644 /tmp/opla-l7.conf "$file"
else
    rm -f "$file"
fi
nginx -t
systemctl reload nginx
trap - ERR
rm -f "$backup" /tmp/opla-l7.conf
printf 'HTTP policy: %s\n' "$action"
REMOTE
