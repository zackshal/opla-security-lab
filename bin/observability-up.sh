#!/usr/bin/env bash
# Один запуск после make up/ready: HTTP-политика, метрики, dashboard, сборщик.
set -euo pipefail
cd "$(dirname "$0")/.."
export LAB_DIR="${LAB_DIR:-}"
[[ -n "$LAB_DIR" ]] || { echo 'BLOCKED: LAB_DIR обязателен; выберите стенд явно' >&2; exit 2; }
./monitoring/manage.sh monitoring-stop
bash bin/security-http.sh apply
./bin/control.sh deploy
./monitoring/manage.sh monitoring-configure
./monitoring/manage.sh monitoring-start
echo 'Откройте dashboard OPLA: страницы XDP and events, HTTP protection, Interface traffic.'
