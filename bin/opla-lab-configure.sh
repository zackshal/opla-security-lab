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

# The root launcher checked the private registry under both lifecycle locks.
# Read only its inherited private snapshot; the SSH user cannot read registry.
python3 -c '
import json
import os
import stat
import sys

lab = sys.argv[1]
try:
    fd = int(sys.argv[2])
    info = os.fstat(fd)
    if (fd < 3 or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o077 or info.st_size > 65536):
        raise ValueError("unsafe snapshot")
    with os.fdopen(os.dup(fd)) as stream:
        records = json.load(stream)
except (OSError, ValueError):
    raise SystemExit("BLOCKED: use the trusted configure launcher; private registry snapshot missing or unsafe")

if (
    not isinstance(records, list) or len(records) != 1
    or not isinstance(records[0], dict)
    or records[0].get("lab") != lab
    or records[0].get("status") != "recorded"
):
    raise SystemExit("BLOCKED: laboratory is not registry-ready")

print("PASS: laboratory registry ready")
' "$LAB_ID" "${3:-}" || exit 2

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
victim_ip="$(python3 bin/state.py "$LAB_DIR" VICTIM_IP)"

# The read-only dependency probe also needs the lab-specific SSH options and
# address resolution. Load the helper before the first ssh_vm/scp_vm call.
source "$ROOT/xdp/lib.sh"

run_step "Cloud-init readiness" \
    make --no-print-directory ready "LAB_DIR=$LAB_DIR"

# Fail before deploying or changing guest services when the immutable victim
# role image lacks the IDS dependencies. Installing packages at configure time
# would make guest state depend on network/package repository availability.
if ssh_vm "$victim_ip" \
    'command -v suricata >/dev/null && python3 -c "import yaml" && { command -v nginx >/dev/null || test -x /usr/sbin/nginx; }'; then
    :
else
    probe_status=$?
    if [[ "$probe_status" -eq 255 ]]; then
        echo "BLOCKED: cannot verify victim dependencies over management SSH (ssh exit 255). No guest configuration has been applied." >&2
    else
        echo "BLOCKED: victim lacks Suricata, PyYAML or nginx (dependency probe exit $probe_status); rebuild the victim role image and create a new lab. No guest configuration has been applied." >&2
    fi
    exit 2
fi
echo "PASS: victim image dependencies (Suricata, PyYAML, nginx)"

run_step "XDP deployment, build and load" \
    make --no-print-directory xdp-all "LAB_DIR=$LAB_DIR"

run_step "HTTP rate policy and JSON access telemetry" \
    env LAB_DIR="$LAB_DIR" bash bin/security-http.sh apply

run_step "Passive distinct-port scan detector" \
    env LAB_DIR="$LAB_DIR" bash bin/scan-detector.sh start

run_step "HTTP JSON telemetry probe" \
    ssh_vm "$victim_ip" \
    'curl --fail --silent --show-error --max-time 5 -o /dev/null http://127.0.0.1/'

run_step "Suricata IDS initialization" \
    make --no-print-directory ids "LAB_DIR=$LAB_DIR"

run_step "Suricata status" \
    make --no-print-directory ids-status "LAB_DIR=$LAB_DIR"

# ids-status prints diagnostics but does not guarantee a nonzero
# exit code when the service is inactive.

run_step "Suricata service active" \
    ssh_vm "$victim_ip" 'sudo systemctl is-active --quiet opla-suricata.service'

verify_telemetry() {
    make --no-print-directory xdp-stats "LAB_DIR=$LAB_DIR" \
        | python3 bin/opla-configure-telemetry.py
}

run_step "Verify XDP, HTTP, scan and IDS telemetry" verify_telemetry

echo
echo "PASS: OPLA laboratory components configured"
echo "Laboratory: $LAB_ID"
