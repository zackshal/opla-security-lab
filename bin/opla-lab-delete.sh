#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo 'BLOCKED: legacy lab-delete is disabled until ownership verification is implemented.' >&2
exit 2
LAB="${LAB_DIR:-}"
[[ -n "$LAB" && "$LAB" == /var/lib/opla/lab-* ]] || { echo 'Нет выбранного LAB_DIR' >&2; exit 2; }
ID="${LAB##*/}"
[[ "${CONFIRM_LAB:-}" == "$ID" ]] || { echo "Удаление отменено. Подтверждение: make lab-delete CONFIRM_LAB=$ID" >&2; exit 2; }
[[ -f "$LAB/state.env" ]] || { echo "Стенд уже удалён: $LAB" >&2; exit 2; }
# Stop only this lab's collector, ignoring if it is already absent.
LAB_DIR="$LAB" "$ROOT/monitoring/manage.sh" monitoring-stop
sudo "$ROOT/bin/cleanup-lab.sh" "$LAB"
# Clear only the matching per-user selection.
python3 - "$ID" <<'PYINNER'
import os, pathlib, sys
selection = pathlib.Path(os.environ.get('XDG_CONFIG_HOME', str(pathlib.Path.home()/'.config'))) / 'opla' / 'selected-lab'
if selection.is_file() and not selection.is_symlink() and selection.read_text().strip() == sys.argv[1]:
    selection.unlink()
    print('Выбор удалённого стенда сброшен')
PYINNER
