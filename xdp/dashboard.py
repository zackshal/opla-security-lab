#!/usr/bin/env python3
"""
dashboard.py — TUI-дашборд для XDP-лабы.

Показывает в реальном времени:
  - Режим XDP (native/generic), статус программы
  - source IP → счётчик пакетов (rate_limit_map)
  - Δ пакетов за тик (pkt/s)
  - Статус DROP (count > THRESHOLD=100)
  - Последнее событие bpf_printk из trace_pipe

Устойчив к форматам bpftool -j:
  value: int | "12345" | [25510] | ["0x3f", ...]
Выход: q
"""
import curses
import json
import os
import socket
import struct
import subprocess
import sys
import time

SSH_KEY = os.path.expanduser("~/.ssh/id_ed25519")
SSH = ["ssh", "-i", SSH_KEY,
       "-o", "StrictHostKeyChecking=no",
       "-o", "UserKnownHostsFile=/dev/null",
       "-o", "LogLevel=ERROR",
       "-o", "ConnectTimeout=3"]
THRESHOLD = 100


def ssh_run(ip, cmd, timeout=5):
    try:
        r = subprocess.run(SSH + [f"student@{ip}", cmd],
                           capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""


def get_mode(ip):
    out = ssh_run(ip, "ip link show ens3 | grep -oE 'xdp[a-z]*' || true")
    return out.strip() or "native"


def get_prog(ip):
    out = ssh_run(ip, "sudo bpftool prog list 2>/dev/null | grep -A1 xdp_ddos_protect | head -2")
    return out.strip() or "(не загружена)"


def _to_int(v):
    """Любое представление числа → int. Никогда не возвращает str."""
    if isinstance(v, bool):        # bool раньше int — bool тоже int
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)        # поддержка "0x1f"
        except ValueError:
            return 0
    if isinstance(v, (list, tuple)):
        if not v:
            return 0
        # Для u64 bpftool может отдавать [lo, hi] или [b0,b1,...] hex-строками
        if all(isinstance(x, str) for x in v):
            try:
                return int(v[0], 0)  # старшие байты — 0, берём младшие
            except ValueError:
                return 0
        return _to_int(v[0])
    return 0


def _to_ip(key):
    """int | [b0,b1,b2,b3] → "a.b.c.d"."""
    if isinstance(key, int):
        try:
            return socket.inet_ntoa(struct.pack("<I", key & 0xFFFFFFFF))
        except (struct.error, ValueError):
            return f"?{key}"
    if isinstance(key, (list, tuple)) and len(key) == 4:
        try:
            return socket.inet_ntoa(bytes(int(x, 0) if isinstance(x, str) else x for x in key))
        except (ValueError, TypeError):
            return f"?{key}"
    return f"?{key}"


def get_map(ip):
    out = ssh_run(ip, "sudo bpftool -j map dump name rate_limit_map 2>/dev/null")
    if not out.strip():
        return []
    try:
        entries = json.loads(out)
    except json.JSONDecodeError:
        return []

    result = []
    for e in entries:
        if "key" not in e or "value" not in e:
            continue
        ip_str = _to_ip(e["key"])
        count = _to_int(e["value"])          # ← гарантированно int
        result.append((ip_str, count))
    # сортируем по int-счётчику, обрабатывая возможные None (защита)
    result.sort(key=lambda x: x[1] if isinstance(x[1], int) else 0, reverse=True)
    return result


def get_last_block(ip):
    out = ssh_run(ip, "sudo timeout 1 cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | grep 'XDP: BLOCK' | tail -1")
    return out.strip() or "(нет событий)"


def draw(stdscr, ip):
    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()

    prev = {}
    tick = 0

    while True:
        if stdscr.getch() in (ord("q"), ord("Q"), 27):
            break

        tick += 1
        mode = get_mode(ip)
        prog = get_prog(ip)
        entries = get_map(ip)
        last_block = get_last_block(ip)

        stdscr.erase()
        stdscr.addstr(0, 0, f"XDP Dashboard — victim {ip}   (q = выход)  tick={tick}", curses.A_BOLD)
        stdscr.addstr(2, 0, f"Режим XDP:     {mode}")
        stdscr.addstr(3, 0, f"Программа:     {prog.splitlines()[0] if prog else '(нет)'}")
        stdscr.addstr(5, 0, f"{'Source IP':<18} {'Packets':>10} {'Δ pkt/s':>10} {'Status':>10}")
        stdscr.addstr(6, 0, "-" * 52)

        total = 0
        for row, (src, count) in enumerate(entries[:15]):
            delta = count - prev.get(src, count)
            prev[src] = count
            status = "DROP" if count > THRESHOLD else "pass"
            attr = curses.A_BOLD if status == "DROP" else curses.A_NORMAL
            stdscr.addstr(7 + row, 0,
                          f"{src:<18} {count:>10} {delta:>10} {status:>10}", attr)
            total += count

        last_row = 7 + min(len(entries), 15)
        stdscr.addstr(last_row, 0, "-" * 52)
        stdscr.addstr(last_row + 1, 0, f"{'TOTAL':<18} {total:>10}")
        stdscr.addstr(last_row + 3, 0, "Последнее событие:")
        stdscr.addstr(last_row + 4, 0, last_block[:200])

        stdscr.refresh()
        time.sleep(1)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <victim_ip>", file=sys.stderr)
        sys.exit(1)
    try:
        curses.wrapper(draw, sys.argv[1])
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
