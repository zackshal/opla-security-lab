#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ACTION="${1:?}"
COMPOSE=(docker compose --env-file monitoring/.env -f monitoring/compose.yaml)
if [[ "$ACTION" == monitoring-up ]]; then
    if [[ ! -f monitoring/.env ]]; then
        (umask 077; python3 -c 'import secrets; print("DB_PASSWORD="+secrets.token_hex(32))' > monitoring/.env)
    fi
    "${COMPOSE[@]}" up -d
    echo 'Zabbix: http://127.0.0.1:8080. Дождитесь экрана входа и смените начальный пароль Admin/zabbix.'
    exit
fi
if [[ "$ACTION" == monitoring-down ]]; then
    # Останавливаем сборщики до остановки сервера, БД сохраняется в volume.
    for unit in $(systemctl --user list-units --plain --no-legend 'opla-monitor-lab-*' | awk '{print $1}'); do
        systemctl --user stop "$unit"
    done
    "${COMPOSE[@]}" down
    exit
fi
LAB_DIR="${LAB_DIR:-$(python3 bin/state.py --latest)}"; export LAB_DIR
LAB_ID="$(python3 bin/state.py "$LAB_DIR" LAB_ID)"
case "$ACTION" in
    monitoring-configure) python3 monitoring/setup.py --lab "$LAB_DIR" ;;
    monitoring-start)
        [[ -f "monitoring/runtime/$LAB_ID/provisioned.json" ]] || { echo 'Сначала make monitoring-configure'; exit 1; }
        ./bin/control.sh deploy
        # Повторный запуск обновляет процесс, чтобы он прочитал новый код.
        systemctl --user stop "opla-monitor-$LAB_ID.service" 2>/dev/null || true
        systemctl --user reset-failed "opla-monitor-$LAB_ID.service" 2>/dev/null || true
        systemd-run --user --collect --unit="opla-monitor-$LAB_ID" \
            --working-directory="$PWD" --setenv="SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519}" \
            /usr/bin/python3 "$PWD/monitoring/bridge.py" --lab "$LAB_DIR"
        echo "Журнал службы: journalctl --user -u opla-monitor-$LAB_ID -f" ;;
    monitoring-stop) systemctl --user stop "opla-monitor-$LAB_ID.service" ;;
    *) echo 'Неизвестная команда' >&2; exit 1;;
esac
