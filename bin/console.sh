#!/usr/bin/env bash
# Usage: console.sh <lab-dir> <attacker|victim|client>
set -euo pipefail
LAB_DIR="${1:-}"; VM="${2:-}"
[[ -n "$LAB_DIR" && -n "$VM" ]] || { echo "Usage: $0 <lab-dir> <vm>"; exit 1; }
[[ -S "${LAB_DIR}/${VM}-console.sock" ]] || { echo "Нет сокета ${LAB_DIR}/${VM}-console.sock"; exit 1; }
exec socat "unix-connect:${LAB_DIR}/${VM}-console.sock" stdio
