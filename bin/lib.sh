#!/usr/bin/env bash
find_free_bridge() {
    local i=0
    while [[ "br-op$i" == "${OPLA_EXCLUDE_BRIDGE:-}" ]] ||
        ip link show "br-op$i" >/dev/null 2>&1 ||
        grep -qsE "^(BRIDGE|MGMT_BRIDGE)=br-op$i$" /var/lib/opla/lab-*/state.env 2>/dev/null; do
        i=$((i+1))
    done
    echo "br-op$i"
}
find_free_subnet_excluding() {
    local excluded="${1:-}"
    python3 "$SCRIPT_DIR/opla_network.py" --exclude-subnet "$excluded"
}
find_free_subnet() {
    python3 "$SCRIPT_DIR/opla_network.py"
}
