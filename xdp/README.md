# eBPF/XDP

Полное описание и команды: [README](../README.md#защита-ebpfxdp).

`xdp_ddos_protect.c` проверяет Ethernet/VLAN/IPv4/TCP, ограничивает начальные SYN по источнику и поддерживает distinct-port scan policy. Default: SYN 100 за 1 секунду, map 4096 sources. Scan threshold: 8 различных портов за фиксированное окно 60 секунд; block TTL 30 секунд.

`scan-policy.py` задаёт off/observe/block и два trusted IPv4 source. Trusted sources обходят scan policy, но не SYN rate limit. При пересоздании карт режим сбрасывается в off. Политика относится к новым SYN, а не ко всем пакетам источника.

Карты: `syn_windows` (state + spin lock), `xdp_policy` (режим + trust), `xdp_stats` (per-CPU u64). Индексы stats: 0 syn, 1 pass, 2 drop, 3 map_full, 4 fragment_drop, 5 xdp_scan_events, 6 xdp_scan_drop. Scan drop входит в общий SYN drop. Повреждённые пакеты могут отбрасываться без увеличения этих SYN-счётчиков.

```bash
make xdp-stats
bash bin/source-map.sh
bash bin/xdp-scan-policy.sh observe
```

Загрузчик отказывается автоматически заменять существующую программу. Native/generic attachment и принятие verifier проверяются на реальном ядре; portable C harness проверяет логику с mock maps/часами. Предельный pps и ускорение относительно netfilter не измерены. Автоматического GC HASH map нет.
