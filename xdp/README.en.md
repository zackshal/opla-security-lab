# eBPF/XDP

[Русский](README.md) · **English**

See the [root README](../README.md#ebpfxdp-protection).

`xdp_ddos_protect.c` validates Ethernet/VLAN/IPv4/TCP, limits initial SYNs per source and supports distinct-port scan detection. Defaults: 100 SYNs per fixed one-second window and 4096 source entries. Scans cross the threshold at eight distinct destination ports in a fixed 60-second window; blocking lasts 30 seconds.

`scan-policy.py` configures off/observe/block and two trusted IPv4 sources. Trust bypasses only scan policy, not the SYN rate limit. New maps default to off. Blocking applies to new SYNs, not every packet or established connection.

Maps: `syn_windows` (state and spin lock), `xdp_policy` (mode and trusted sources), `xdp_stats` (per-CPU u64). Statistics indices: 0 syn, 1 pass, 2 drop, 3 map_full, 4 fragment_drop, 5 xdp_scan_events, 6 xdp_scan_drop. Scan drops are included in total SYN drops. Malformed packets may be dropped without incrementing SYN counters.

```bash
make xdp-stats
bash bin/source-map.sh
bash bin/xdp-scan-policy.sh observe
```

The loader refuses to replace an attached program automatically. Native/generic attachment and verifier acceptance require a real kernel; the portable C harness uses mock maps and time. Maximum pps and acceleration versus netfilter have not been measured. The HASH map has no automatic GC.
