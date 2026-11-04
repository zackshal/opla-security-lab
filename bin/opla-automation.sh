#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${1:-validate}"

STATE_DIR="$HOME/.local/state/opla-automation"
TEST_DIR="$HOME/.local/share/opla-acceptance/debian12-amd64"
INVENTORY="$TEST_DIR/inventory.yml"
# Keep the default deterministic and user-local; CI or an operator may still
# provide an isolated environment explicitly through OPLA_ANSIBLE_VENV.
VENV_DIR="${OPLA_ANSIBLE_VENV:-$HOME/.local/share/opla-acceptance/ansible-venv}"

mkdir -p -m 700 "$STATE_DIR"

# Prevent concurrent automation runs.
exec 9>"$STATE_DIR/automation.lock"
flock -n 9 || {
    echo "BLOCKED: another OPLA automation is running"
    exit 2
}

LOG="$STATE_DIR/run-$(date +%Y%m%d-%H%M%S).log"

exec > >(tee -a "$LOG") 2>&1

echo "===== OPLA AUTOMATION ====="
echo "Mode: $MODE"
echo "Commit: $(git rev-parse --short HEAD)"
echo "Log: $LOG"

validate() {
    echo "===== SOURCE VALIDATION ====="

    bash -n \
        bin/create-lab.sh \
        bin/prepare-image.sh

    echo "===== IMAGE INTEGRITY ====="
    python3 bin/opla-image-verify.py

    echo "===== REGRESSION TESTS ====="
    make check

    echo "PASS: local validation"
}

check_guest_target() {
    echo "===== VERIFY EXECUTION TARGET ====="

    python3 - "$INVENTORY" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit("BLOCKED: acceptance inventory missing")

inventory = yaml.safe_load(path.read_text())

hosts = inventory["all"]["children"]["opla_hosts"]["hosts"]
if list(hosts) != ["opla-debian12"]:
    raise SystemExit("BLOCKED: unexpected inventory hosts")

host = hosts["opla-debian12"]

expected = {
    "ansible_host": "127.0.0.1",
    "ansible_port": 22229,
    "ansible_user": "opla",
    "ansible_connection": "ssh",
}

for key, value in expected.items():
    if host.get(key) != value:
        raise SystemExit(f"BLOCKED: unexpected {key}")

ssh_key = str(Path.home() / ".ssh/id_ed25519")
if host.get("ansible_ssh_private_key_file") != ssh_key:
    raise SystemExit("BLOCKED: unexpected SSH key")

print("PASS: known Debian 12 acceptance target")
PY

    [[ -f "$VENV_DIR/bin/ansible-playbook" ]] || {
        echo "BLOCKED: Ansible virtual environment missing"
        exit 2
    }

    local ssh_options=(
        -i "$HOME/.ssh/id_ed25519"
        -p 22229
        -o IdentitiesOnly=yes
        -o StrictHostKeyChecking=yes
        -o "UserKnownHostsFile=$TEST_DIR/known_hosts"
        -o ConnectTimeout=5
    )

    ssh "${ssh_options[@]}" opla@127.0.0.1 \
        'test "$(cat /etc/debian_version | cut -d. -f1)" = 12 &&
         test "$(uname -m)" = x86_64 &&
         test "$(hostname)" = opla-acceptance' || {
        echo "BLOCKED: guest identity mismatch"
        exit 2
    }

    echo "PASS: guest OS and hostname"
}

playbook() {
    ANSIBLE_CONFIG="$ROOT/ansible/ansible.cfg" \
        "$VENV_DIR/bin/python" \
        "$VENV_DIR/bin/ansible-playbook" \
        -i "$INVENTORY" \
        "$@"
}

provision() {
    playbook ansible/playbooks/provision.yml \
        -e opla_allow_provision=true \
        -e opla_host_manage_packages=true \
        -e opla_host_dedicated_target=true
}

remote_acceptance() {
    echo "===== GUEST PROVISIONING ====="
    provision

    echo "===== GUEST PREFLIGHT ====="
    playbook ansible/playbooks/preflight.yml \
        -e opla_require_ready=true

    echo "===== GUEST ACCEPTANCE ====="
    playbook ansible/playbooks/acceptance.yml

    echo "===== IDEMPOTENCY ====="

    local second_log="$STATE_DIR/idempotency-$(date +%s).log"

    provision | tee "$second_log"

    python3 - "$second_log" <<'PY'
import re
import sys
from pathlib import Path

log = Path(sys.argv[1]).read_text()

matches = re.findall(
    r"^opla-debian12\s*:\s*ok=\d+\s+changed=(\d+)"
    r"\s+unreachable=(\d+)\s+failed=(\d+)",
    log,
    flags=re.MULTILINE
)

if not matches:
    raise SystemExit("FAIL: Ansible recap not found")

changed, unreachable, failed = map(int, matches[-1])

if (changed, unreachable, failed) != (0, 0, 0):
    raise SystemExit(
        "FAIL: provisioning is not idempotent "
        f"(changed={changed}, unreachable={unreachable}, failed={failed})"
    )

print("PASS: idempotent provisioning, changed=0")
PY
}

case "$MODE" in
    probe)
        # Read-only remote inspection of the pinned Debian 12 target.
        # No provisioning, package installation or VM lifecycle.
        check_guest_target
        echo "===== GUEST READ-ONLY PREFLIGHT ====="
        playbook ansible/playbooks/preflight.yml
        ;;
    validate)
        validate
        ;;
    guest)
        check_guest_target
        remote_acceptance
        ;;
    all)
        validate
        check_guest_target
        remote_acceptance
        ;;
    *)
        echo "Usage: $0 {probe|validate|guest|all}" >&2
        exit 2
        ;;
esac

echo "===== AUTOMATION PASS ====="
echo "Log: $LOG"
