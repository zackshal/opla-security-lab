#!/usr/bin/env bash
# Lifecycle: bootstrap → images → install → create → ready → activate → scenario.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

LIFECYCLE_STATE="$OUTPUT_DIR/lifecycle.env"
: > "$LIFECYCLE_STATE"

# 1. Bootstrap & images
step bootstrap make bootstrap
step images    make images

# 2. Snapshot install
SNAP_OUT="$(python3 bin/opla-system-install.py --source "$PWD" 2>&1 | tee -a "$OUTPUT_DIR/logs/install.log")"
DIGEST="$(echo "$SNAP_OUT" | grep -oE '[a-f0-9]{64}' | head -1)"
[[ -n "$DIGEST" ]] || die "install: no SHA-256 in output"
if [[ -e /opt/opla ]]; then
  log "install: /opt/opla already exists; assuming same snapshot (runner should be clean)"
else
  sudo python3 bin/opla-system-install.py --source "$PWD" --install \
       --destination /opt/opla --expected-sha256 "$DIGEST" 2>&1 | tee -a "$OUTPUT_DIR/logs/install.log"
  python3 /opt/opla/bin/opla-cli-install.py install 2>&1 | tee -a "$OUTPUT_DIR/logs/install.log"
  sudo install -d -o root -g root -m 0755 /var/lib/opla
fi

# 3. Create lab (autonomous, non-interactive by flag)
CREATE_OUT="$(step lab_create opla lab create --confirm-host-changes 2>&1 | tee -a "$OUTPUT_DIR/logs/lab_create.log")" || true
LAB_ID="$(echo "$CREATE_OUT" | grep -oE 'lab-[A-Za-z0-9]{8}' | tail -1)"
if [[ -z "$LAB_ID" ]]; then
  LAB_ID="$(opla lab list 2>/dev/null | grep -oE 'lab-[A-Za-z0-9]{8}' | tail -1)"
fi
[[ -n "$LAB_ID" ]] || die "could not resolve LAB_ID"
echo "LAB_ID=$LAB_ID" >> "$LIFECYCLE_STATE"
log "LAB_ID=$LAB_ID"

opla lab select "$LAB_ID" 2>&1 | tee -a "$OUTPUT_DIR/logs/select.log"
step lab_ready opla lab ready --lab "$LAB_ID"

# 4. Activate. Zabbix prompts: prefer env, otherwise mark PARTIAL.
if [[ -n "${OPLA_ZABBIX_USER:-}" && -n "${OPLA_ZABBIX_PASSWORD:-}" ]]; then
  step lab_activate opla lab activate "$LAB_ID"
else
  log "WARN: OPLA_ZABBIX_* not set; activation may prompt. Will mark zabbix=SKIPPED."
  step lab_activate opla lab activate "$LAB_ID" || log "activate failed or interrupted"
fi

# 5. Before-state
step xdp_stats_before opla xdp stats
step ids_status_before opla ids status
capture "$OUTPUT_DIR/evidence/bpftool-prog-before.json"  bpftool prog show -j
capture "$OUTPUT_DIR/evidence/bpftool-map-before.json"   bpftool map  show -j
capture "$OUTPUT_DIR/evidence/nft-ruleset-before.txt"    sudo nft list ruleset
capture "$OUTPUT_DIR/evidence/ip-addr-before.txt"        ip addr
capture "$OUTPUT_DIR/evidence/ip-route-before.txt"       ip route
capture "$OUTPUT_DIR/evidence/ip-link-before.txt"        ip link

# 6. Scenario check + run
step scenario_check opla scenario check "$OPLA_SCENARIO" --lab "$LAB_ID"
step scenario_run   opla scenario run   "$OPLA_SCENARIO" --lab "$LAB_ID" --confirm "$LAB_ID"

# 7. After-state
step xdp_stats_after opla xdp stats
step ids_status_after opla ids status
capture "$OUTPUT_DIR/evidence/bpftool-prog-after.json"   bpftool prog show -j
capture "$OUTPUT_DIR/evidence/bpftool-map-after.json"    bpftool map  show -j
capture "$OUTPUT_DIR/evidence/nft-ruleset-after.txt"     sudo nft list ruleset
capture "$OUTPUT_DIR/evidence/ip-addr-after.txt"         ip addr
capture "$OUTPUT_DIR/evidence/ip-route-after.txt"        ip route
capture "$OUTPUT_DIR/evidence/ip-link-after.txt"         ip link

# 8. Optional recovery drill
if [[ "$OPLA_SKIP_RECOVERY" != "1" ]]; then
  T0="$(date +%s)"
  step lab_stop    opla lab stop  --lab "$LAB_ID"
  step lab_start   opla lab start --lab "$LAB_ID"
  step lab_ready2  opla lab ready --lab "$LAB_ID"
  step xdp_stats_after_recovery opla xdp stats
  echo "RECOVERY_DOWNTIME_S=$(( $(date +%s) - T0 ))" >> "$LIFECYCLE_STATE"
fi
