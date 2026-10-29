#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
lab_id="${1:-}"
confirmation="${2:-}"

if [[ ! "$lab_id" =~ ^lab-[A-Za-z0-9]{4,32}$ || "$confirmation" != "$lab_id" ]]; then
    echo "BLOCKED: pass the exact lab ID twice as confirmation" >&2
    exit 2
fi

python3 - "$ROOT" <<'PY'
import os
from pathlib import Path
import stat
import sys

project = Path(sys.argv[1])
for directory in (project, *project.parents):
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
        raise SystemExit(
            "BLOCKED: lab activation needs the root-owned trusted OPLA "
            "installation. This checkout is user-writable; install the reviewed "
            "snapshot using docs/local-system-install.md, then run its CLI."
        )
for name in ("opla-lab-configure-launcher.py", "opla-lifecycle-lock.py",
             "opla-lab-configure.sh", "opla-create-launcher.py",
             "create-lab.sh", "opla-registry.py"):
    source = project / "bin" / name
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or info.st_nlink != 1):
        raise SystemExit(
            f"BLOCKED: untrusted privileged source {source}; install the reviewed "
            "root-owned snapshot using docs/local-system-install.md."
        )
PY

lab_dir="/var/lib/opla/$lab_id"
python3 bin/state.py "$lab_dir" LAB_ID >/dev/null || {
    echo "BLOCKED: lab state is missing or invalid: $lab_id" >&2
    exit 2
}
export LAB_DIR="$lab_dir"

step() {
    local label="$1"
    shift
    printf '\n===== %s =====\n' "$label"
    "$@"
}

echo "Активация стенда $lab_id: настройка защиты, Zabbix dashboard и сборщика."
step "Guest protection and telemetry" make --no-print-directory lab-configure "LAB=$lab_id" "CONFIRM=$confirmation"
step "Start Zabbix stack" make --no-print-directory monitoring-up
step "Create or update dashboard objects" make --no-print-directory monitoring-configure
step "Start per-lab telemetry collector" make --no-print-directory monitoring-start

echo
echo "PASS: защита и сбор telemetry настроены."
echo "Zabbix: http://127.0.0.1:8080"
echo "Панель: OPLA (5 страниц); первая загрузка Latest data может занять несколько интервалов."
