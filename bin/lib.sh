#!/usr/bin/env bash
# Подключается через `source` из create-lab.sh и cleanup-lab.sh

find_free_bridge() {
    local i=0
    while ip link show "br-lab${i}" &>/dev/null; do
        i=$((i + 1))
    done
    echo "br-lab${i}"
}

find_free_subnet() {
    local second=64
    while [ $second -le 127 ]; do
        local third=0
        while [ $third -le 255 ]; do
            local fourth=0
            while [ $fourth -le 248 ]; do
                local gw="100.${second}.${third}.${fourth}.1"
                if ! ip -4 addr show | grep -qF "${gw}/"; then
                    echo "100.${second}.${third}.${fourth}"
                    return 0
                fi
                fourth=$((fourth + 8))
            done
            third=$((third + 1))
        done
        second=$((second + 1))
    done
    return 1
}
