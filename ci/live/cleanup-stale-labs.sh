#!/usr/bin/env bash
# Manual recovery: stop and delete one explicitly selected stale lab.
set -euo pipefail
id="${1:-}"
[[ "$#" -eq 1 && "$id" =~ ^lab-[A-Za-z0-9]{8}$ ]] || {
  echo "Usage: $0 lab-XXXXXXXX" >&2
  exit 2
}
echo "Stale: $id"
read -r -p "Delete $id after stop? [y/N] " yn
[[ "$yn" == "y" ]] || exit 0
if ! LAB_DIR="/var/lib/opla/$id" opla lab stop; then
  echo "ERROR: stop failed; refusing delete of $id" >&2
  exit 1
fi
if ! opla lab delete "$id" --confirm-lab "$id"; then
  echo "ERROR: delete failed for $id" >&2
  exit 1
fi
