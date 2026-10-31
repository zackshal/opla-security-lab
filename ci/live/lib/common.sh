#!/usr/bin/env bash
# Common helpers for live-acceptance. Source this from run-live-acceptance.sh.

set -euo pipefail

# --- Platform detection ---
CI_PLATFORM="${CI_PLATFORM:-auto}"
if [[ "$CI_PLATFORM" == "auto" ]]; then
  if   [[ -n "${GITLAB_CI:-}"      ]]; then CI_PLATFORM="gitlab"
  elif [[ -n "${GITHUB_ACTIONS:-}" ]]; then CI_PLATFORM="github"
  else                                     CI_PLATFORM="local"
  fi
fi

# --- Paths ---
: "${OPLA_LAB_PREFIX:=live}"
: "${OPLA_SCENARIO:=syn-scan-baseline}"
: "${OPLA_SKIP_RECOVERY:=0}"
: "${OPLA_KEEP_LAB:=0}"
: "${OPLA_DRY_RUN:=0}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${CI_PROJECT_DIR:-${GITHUB_WORKSPACE:-$ROOT_DIR}}/live-acceptance-output}"
mkdir -p "$OUTPUT_DIR"/{logs,evidence,reports,manifests}
LIVE_LOG="$OUTPUT_DIR/logs/run.log"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LIVE_LOG"; }
die() { log "ERROR: $*"; exit 1; }

# Run a step, log duration, record into steps.jsonl. Fail-closed on error.
# Usage: step <name> <command...>
step() {
  local name="$1"; shift
  local t0 t1 rc=0
  t0="$(date +%s)"
  log "START: $name"
  if [[ "$OPLA_DRY_RUN" == "1" ]]; then
    log "DRY-RUN: would execute: $*"
  else
    "$@" 2>&1 | tee -a "$OUTPUT_DIR/logs/${name}.log" || rc=$?
  fi
  t1="$(date +%s)"
  local dur=$((t1 - t0))
  local status="PASS"; [[ $rc -ne 0 ]] && status="FAIL"
  jq -nc --arg n "$name" --arg s "$status" --argjson d "$dur" --argjson rc "$rc" \
    '{name:$n,status:$s,duration_s:$d,exit_code:$rc}' >> "$OUTPUT_DIR/steps.jsonl"
  log "END: $name status=$status duration=${dur}s rc=$rc"
  return $rc
}

# Capture stdout of a command into a file; never fail the whole run.
capture() {
  local out="$1"; shift
  { "$@" >"$out" 2>&1; } || true
}

# SSH helper. Tries to resolve victim/attacker/client mgmt IP from state.env.
resolve_vm_addr() {
  local lab_id="$1" role="$2"
  local state="/var/lib/opla/labs/$lab_id/state.env"
  [[ -r "$state" ]] || return 1
  # shellcheck disable=SC1090
  source "$state" 2>/dev/null || return 1
  local u; u="$(echo "$role" | tr '[:lower:]' '[:upper:]')"
  local v
  for v in "${u}_MGMT_IP" "${u}_MANAGEMENT_IP" "${u}_IP"; do
    [[ -n "${!v:-}" ]] && { echo "${!v}"; return 0; }
  done
  return 1
}

cleanup_lab() {
  local lab_id="$1"
  [[ -z "$lab_id" ]] && return 0
  [[ "$OPLA_KEEP_LAB" == "1" ]] && { log "KEEP_LAB=1: leaving $lab_id"; return 0; }
  log "cleanup: stopping lab $lab_id"
  opla monitoring stop       >>"$OUTPUT_DIR/logs/cleanup.log" 2>&1 || true
  opla lab stop --lab "$lab_id" >>"$OUTPUT_DIR/logs/cleanup.log" 2>&1 || true
  opla lab delete --lab "$lab_id" --confirm "$lab_id" >>"$OUTPUT_DIR/logs/cleanup.log" 2>&1 || true
}

trap '__trap_rc=$?; log "trap: exit rc=$__trap_rc"; [[ -n "${LAB_ID:-}" ]] && cleanup_lab "$LAB_ID"; exit $__trap_rc' EXIT INT TERM
