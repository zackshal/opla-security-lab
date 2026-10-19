#!/bin/bash
IFACE="${1:-}"
[ -z "$IFACE" ] && exit 0
IP_BIN="$(command -v ip || echo /sbin/ip)"
"$IP_BIN" link set "$IFACE" down 2>/dev/null || true
"$IP_BIN" link del "$IFACE" 2>/dev/null || true
exit 0
