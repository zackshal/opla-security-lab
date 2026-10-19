#!/bin/bash
IFACE="$1"
ip link set "$IFACE" down 2>/dev/null || true
ip link del "$IFACE" 2>/dev/null || true
