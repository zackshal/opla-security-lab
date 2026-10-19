#!/bin/bash
IFACE="${1:-}"
[ -z "$IFACE" ] && { echo "qemu-ifup: пустой \$1" >&2; exit 1; }
IP_BIN="$(command -v ip || echo /sbin/ip)"
"$IP_BIN" link set "$IFACE" up
"$IP_BIN" link set "$IFACE" master __BRIDGE__
