#!/usr/bin/env bash

find_free_bridge() {
    local i=0
    while ip link show "br-lab${i}" &>/dev/null; do
        i=$((i + 1))
    done
    echo "br-lab${i}"
}

find_free_subnet() {
    local s t f
    for s in $(seq 64 127); do
        for t in $(seq 0 255); do
            for f in $(seq 0 8 248); do
                local gw="100.${s}.${t}.$((f + 1))"
                if ! ip -4 addr show | grep -qF "${gw}/"; then
                    echo "100.${s}.${t}.${f}"
                    return 0
                fi
            done
        done
    done
    return 1
}
