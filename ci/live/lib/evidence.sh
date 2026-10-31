#!/usr/bin/env bash
# Collect versions, image hashes, scenario reports. Build manifest.json.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
: "${LAB_ID:?lifecycle must set LAB_ID}"

EV="$OUTPUT_DIR/evidence"

# --- Host versions ---
capture "$EV/host-dpkg.txt"          dpkg -l
capture "$EV/host-pip.txt"           python3 -m pip freeze
capture "$EV/host-docker-images.txt" docker images --digests 2>/dev/null || true
capture "$EV/host-ps.txt"            ps aux
capture "$EV/host-git.txt"           git -c core.abbrev=40 rev-parse HEAD
capture "$EV/host-git-status.txt"    git status --short

# --- Image hashes ---
IMAGES_DIR="$ROOT_DIR/images"
if [[ -d "$IMAGES_DIR" ]]; then
  ( cd "$IMAGES_DIR" && find . -maxdepth 2 -name '*.qcow2' -type f -print0 \
      | xargs -0 -r sha256sum ) > "$EV/images.sha256" 2>/dev/null || true
fi
git archive HEAD | sha256sum > "$EV/repo-archive.sha256" 2>/dev/null || true

# --- Scenario reports ---
LAB_DIR="/var/lib/opla/labs/$LAB_ID"
if [[ -d "$LAB_DIR" ]]; then
  sudo mkdir -p "$EV/lab-reports"
  sudo cp -a "$LAB_DIR"/. "$EV/lab-reports/" 2>/dev/null || true
  # Narrow collection: JSON, EVE, logs, client probes
  find "$EV/lab-reports" -type f \( -name '*.json' -o -name '*.jsonl' -o -name '*.log' -o -name 'eve.*' \) \
      -exec sha256sum {} \; > "$EV/lab-reports.sha256" 2>/dev/null || true
fi

# --- VM package versions (best effort via SSH) ---
for role in victim attacker client; do
  ADDR="$(resolve_vm_addr "$LAB_ID" "$role" || true)"
  KEY="$( [[ -r "$LAB_DIR/$role/id_ed25519" ]] && echo "$LAB_DIR/$role/id_ed25519" \
         || [[ -r "$LAB_DIR/id_ed25519" ]]         && echo "$LAB_DIR/id_ed25519" || true )"
  if [[ -n "$ADDR" && -n "$KEY" ]]; then
    capture "$EV/vm-${role}-dpkg.txt" \
      ssh -i "$KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
          "root@$ADDR" 'dpkg -l' || true
  else
    log "WARN: cannot resolve SSH for $role; versions unavailable"
    : > "$EV/vm-${role}-dpkg.txt"
  fi
done

# --- Manifest ---
jq -n \
  --arg platform "$CI_PLATFORM" \
  --arg commit "$(cat "$EV/host-git.txt" 2>/dev/null || echo unknown)" \
  --arg dirty "$(cat "$EV/host-git-status.txt" 2>/dev/null || true)" \
  --arg lab_id "$LAB_ID" \
  --arg scenario "$OPLA_SCENARIO" \
  --arg started "$STARTED_AT" \
  --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg recovery "$(grep RECOVERY_DOWNTIME_S "$OUTPUT_DIR/lifecycle.env" 2>/dev/null || true)" \
  --slurpfile preflight  "$OUTPUT_DIR/evidence/preflight.json" \
  --slurpfile steps      "$OUTPUT_DIR/steps.jsonl" \
  '{
    schema_version: 1,
    platform: $platform,
    commit: $commit,
    git_dirty: ($dirty|length>0),
    lab: {id: $lab_id, scenario: $scenario},
    started_at: $started, finished_at: $finished,
    preflight: $preflight[0],
    recovery: $recovery,
    steps: $steps,
    artifacts: []   # filled by verify-evidence.py after hashing
  }' > "$OUTPUT_DIR/manifest.json"

# Add artifact hashes
python3 "$ROOT_DIR/ci/live/verify-evidence.py" --fill-hashes "$OUTPUT_DIR" || true
