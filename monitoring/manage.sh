#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ACTION="${1:?}"
COMPOSE=(docker compose --env-file "${XDG_CONFIG_HOME:-$HOME/.config}/opla/monitoring.env" -f monitoring/compose.yaml)
if [[ "$ACTION" == monitoring-up ]]; then
    ENV_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/opla/monitoring.env"
    ENV_DIR="$(dirname "$ENV_FILE")"
    mkdir -p -m 700 "$ENV_DIR"
    [[ ! -L "$ENV_FILE" ]] || { echo 'BLOCKED: monitoring env file is a symlink' >&2; exit 2; }
    if [[ ! -e "$ENV_FILE" ]]; then
        python3 bin/opla_monitoring_env.py \
            --source "$PWD/monitoring/.env" --destination "$ENV_FILE" \
            --owner-uid "$(id -u)" --owner-gid "$(id -g)" --home "$HOME"
    fi
    if [[ ! -e "$ENV_FILE" ]]; then
        if docker volume inspect opla-monitoring_db-data >/dev/null 2>&1; then
            echo "BLOCKED: existing Zabbix database has no user config or legacy monitoring/.env at $ENV_FILE." >&2
            echo 'Restore the original DB_PASSWORD from a protected backup; a new password cannot unlock the existing database.' >&2
            exit 2
        fi
        (umask 077; python3 -c 'import secrets; print("DB_PASSWORD="+secrets.token_hex(32))' > "$ENV_FILE")
    fi
    [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" && "$(stat -c '%a' "$ENV_FILE")" == 600 && "$(stat -c '%u' "$ENV_FILE")" == "$(id -u)" ]] || {
        echo "BLOCKED: $ENV_FILE must be a regular mode-0600 file" >&2; exit 2;
    }
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
MONITORING_STATE="$HOME/.local/state/opla/monitoring"
case "$ACTION" in
    monitoring-configure) python3 monitoring/setup.py --lab "$LAB_DIR" ;;
    monitoring-start)
        [[ -f "$MONITORING_STATE/runtime/$LAB_ID/provisioned.json" ]] || { echo 'Сначала make monitoring-configure'; exit 1; }
        ./bin/control.sh deploy
        # Повторный запуск обновляет процесс, чтобы он прочитал новый код.
        systemctl --user stop "opla-monitor-$LAB_ID.service" 2>/dev/null || true
        systemctl --user reset-failed "opla-monitor-$LAB_ID.service" 2>/dev/null || true
        systemd-run --user --collect --unit="opla-monitor-$LAB_ID" \
            --working-directory="$PWD" --setenv="SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519}" \
            /usr/bin/python3 "$PWD/monitoring/bridge.py" --lab "$LAB_DIR"
        echo "Журнал службы: journalctl --user -u opla-monitor-$LAB_ID -f" ;;
    monitoring-stop)
        unit="opla-monitor-$LAB_ID.service"
        if [[ "$(systemctl --user show "$unit" -p LoadState --value)" != not-found ]]; then
            systemctl --user stop "$unit"
        else
            echo 'Сборщик уже остановлен'
        fi ;;
    *) echo 'Неизвестная команда' >&2; exit 1;;
esac
