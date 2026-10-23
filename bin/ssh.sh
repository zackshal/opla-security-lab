#!/usr/bin/env bash
set -euo pipefail
export LAB_DIR="${1:?Укажите каталог стенда}"
exec "$(dirname "$0")/control.sh" ssh "${2:-victim}"
