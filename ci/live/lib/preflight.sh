#!/usr/bin/env bash
# Preflight: fail-closed if host is unsuitable for live OPLA run.

set -euo pipefail
: "${OUTPUT_DIR:?source lib/common.sh first}"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

PRE="$OUTPUT_DIR/evidence/preflight.json"
declare -A R=()

R[platform]="$(uname -s)"
R[arch]="$(uname -m)"
R[kernel]="$(uname -r)"
R[os_id]="$(grep -E '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo unknown)"
R[os_version]="$(grep -E '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo unknown)"

# KVM
if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then R[kvm]="ok"; else R[kvm]="missing_or_no_access"; fi

# Tools used by bootstrap, image preparation, lifecycle, activation and evidence.
REQUIRED_TOOLS=(
  qemu-system-x86_64 qemu-img virt-customize virt-resize cloud-localds dnsmasq
  ip nft flock systemd-run systemctl python3 make git jq clang bpftool curl
  ssh scp docker
)
for t in "${REQUIRED_TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then R["tool_$t"]="ok"; else R["tool_$t"]="missing"; fi
done
if docker compose version >/dev/null 2>&1; then
  R[docker_compose]="ok"
else
  R[docker_compose]="missing"
fi

# Free RAM (MiB)
RAM_MB="$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
R[ram_available_mb]="$RAM_MB"

# Free disk (GiB) on /var/lib
DISK_GIB="$(df -BG --output=avail /var/lib 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)"
R[disk_available_gib]="$DISK_GIB"

# sudo -n (must be preconfigured on runner)
if sudo -n true >/dev/null 2>&1; then R[sudo_nopasswd]="ok"; else R[sudo_nopasswd]="missing"; fi

# Outbound (bootstrap downloads Debian image)
if curl -fsI --max-time 10 https://cloud.debian.org/images/cloud/ >/dev/null 2>&1; then
  R[outbound_debian]="ok"; else R[outbound_debian]="missing"; fi

# Emit JSON with a real encoder; shell quoting (%q) is not JSON quoting.
json_args=()
for k in "${!R[@]}"; do
  json_args+=("$k" "${R[$k]}")
done
python3 - "$PRE" "${json_args[@]}" <<'PY'
import json
import sys
from pathlib import Path

if len(sys.argv[2:]) % 2:
    raise SystemExit("preflight JSON encoder received an uneven key/value list")
values = dict(zip(sys.argv[2::2], sys.argv[3::2]))
Path(sys.argv[1]).write_text(json.dumps(values, ensure_ascii=False, sort_keys=True) + "\n")
PY

# Fail-closed decisions
fails=()
[[ "${R[kvm]}" == "ok" ]] || fails+=("KVM")
[[ "${R[ram_available_mb]}" -ge 5120 ]] || fails+=("RAM<5120MiB")
[[ "${R[disk_available_gib]}" -ge 30 ]] || fails+=("disk<30GiB")
[[ "${R[sudo_nopasswd]}" == "ok" ]] || fails+=("sudo -n")
[[ "${R[outbound_debian]}" == "ok" ]] || fails+=("no outbound to cloud.debian.org")
for t in "${REQUIRED_TOOLS[@]}"; do
  [[ "${R[tool_$t]}" == "ok" ]] || fails+=("tool:$t")
done

if [[ ${#fails[@]} -gt 0 ]]; then
  log "PREFLIGHT FAILED: ${fails[*]}"
  jq -n --arg f "${fails[*]}" '{status:"BLOCKED",blockers:($f|split(" "))}' > "$OUTPUT_DIR/evidence/preflight-decision.json"
  exit 1
fi
log "PREFLIGHT PASS"
