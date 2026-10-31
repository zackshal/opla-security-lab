#!/usr/bin/env bash
# Manual recovery: list and delete stale lab-live-* left by crashed runs.
set -euo pipefail
PREFIX="${OPLA_LAB_PREFIX:-live}"
opla lab list 2>/dev/null | grep -E "lab-${PREFIX}" | while read -r line; do
  id="$(echo "$line" | grep -oE 'lab-[A-Za-z0-9]{8}')"
  [[ -z "$id" ]] && continue
  echo "Stale: $id"; read -r -p "Delete $id? [y/N] " yn
  [[ "$yn" == "y" ]] || continue
  opla lab stop  --lab "$id" || true
  opla lab delete --lab "$id" --confirm "$id" || true
done
