#!/usr/bin/env bash
# Один запуск после make up/ready: HTTP-политика, метрики, dashboard, сборщик.
set -euo pipefail
cd "$(dirname "$0")/.."
export LAB_DIR="${LAB_DIR:-$(python3 bin/state.py --latest)}"
[[ -n "$LAB_DIR" ]] || { echo 'Сначала make up и make ready' >&2; exit 1; }
./monitoring/manage.sh monitoring-stop
bash bin/security-http.sh apply
./bin/control.sh deploy
./monitoring/manage.sh monitoring-configure
./monitoring/manage.sh monitoring-start
echo 'Откройте dashboard OPLA: страницы XDP and events, HTTP protection, Interface traffic.'
