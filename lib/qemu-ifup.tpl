#!/bin/bash
set -e
IFACE="$1"
ip link set "$IFACE" up
ip link set "$IFACE" master __BRIDGE__
