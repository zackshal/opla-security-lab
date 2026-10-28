#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LAB_ID="${1:-}"
CONFIRM="${2:-}"

if [[ ! "$LAB_ID" =~ ^lab-[A-Za-z0-9]{4,32}$ ]]; then
    echo "BLOCKED: invalid laboratory ID" >&2
    exit 2
fi

if [[ "$CONFIRM" != "$LAB_ID" ]]; then
    echo "BLOCKED: exact laboratory confirmation required" >&2
    exit 2
fi

LAB_DIR="/var/lib/opla/$LAB_ID"

if [[ ! -d "$LAB_DIR" || -L "$LAB_DIR" ]]; then
    echo "BLOCKED: laboratory directory missing or unsafe" >&2
    exit 2
fi

# Verify that the selected directory actually describes this laboratory.
ACTUAL_ID="$(python3 bin/state.py "$LAB_DIR" LAB_ID)"

if [[ "$ACTUAL_ID" != "$LAB_ID" ]]; then
    echo "BLOCKED: laboratory state identity mismatch" >&2
    exit 2
fi

export LAB_DIR

# Only a successfully created, registry-ready lab can be configured.
registry_json="$(python3 bin/opla-registry.py list --lab "$LAB_ID")" || {
    echo "BLOCKED: registry inspection failed" >&2
    exit 2
}

printf '%s\n' "$registry_json" | python3 -c '
import json
import sys

lab = sys.argv[1]
records = json.load(sys.stdin)

if (
    len(records) != 1
    or records[0].get("lab") != lab
    or records[0].get("status") != "recorded"
):
    raise SystemExit("BLOCKED: laboratory is not registry-ready")

print("PASS: laboratory registry ready")
' "$LAB_ID" || exit 2

for role in attacker victim client; do
    unit="qemu-${LAB_ID}-${role}.service"
    if ! systemctl is-active --quiet "$unit"; then
        echo "BLOCKED: VM inactive: $unit" >&2
        exit 2
    fi
done

echo "PASS: all three VM services active"


run_step() {
    local name="$1"
    shift

    printf '\n===== %s =====\n' "$name"

    if ! "$@"; then
        echo "BLOCKED: failed step: $name" >&2
        echo "Laboratory retained for diagnosis: $LAB_DIR" >&2
        exit 2
    fi

    echo "PASS: $name"
}

echo "OPLA laboratory configuration"
echo "Laboratory: $LAB_ID"

run_step "Cloud-init readiness" \
    make --no-print-directory ready "LAB_DIR=$LAB_DIR"

run_step "XDP deployment, build and load" \
    make --no-print-directory xdp-all "LAB_DIR=$LAB_DIR"

run_step "Suricata IDS initialization" \
    make --no-print-directory ids "LAB_DIR=$LAB_DIR"

run_step "Suricata status" \
    make --no-print-directory ids-status "LAB_DIR=$LAB_DIR"

# ids-status prints diagnostics but does not guarantee a nonzero
# exit code when the service is inactive.
source "$ROOT/xdp/lib.sh"
victim_ip="$(python3 bin/state.py "$LAB_DIR" VICTIM_IP)"

run_step "Suricata service active" \
    ssh_vm "$victim_ip" 'sudo systemctl is-active --quiet opla-suricata.service'

run_step "XDP/IDS telemetry" \
    make --no-print-directory xdp-stats "LAB_DIR=$LAB_DIR"

echo
echo "PASS: OPLA laboratory components configured"
echo "Laboratory: $LAB_ID"
