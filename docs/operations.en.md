# Operations and diagnostics

[Русский](operations.md) · **English**

Run commands from the repository root. Select the lab first:

```bash
export LAB_DIR="$(python3 bin/state.py --latest)"
printf '%s\n' "$LAB_DIR"
python3 bin/state.py "$LAB_DIR" LAB_ID
python3 bin/state.py "$LAB_DIR" VICTIM_IP
```

`--latest` uses state.env mtime; it does not confirm a running VM. Set an explicit known `LAB_DIR` for multiple labs. Do not source state.env as shell code: state.py validates ownership, path and values.

## VM services

```bash
make ready
make ssh VM=victim
```

Inside victim:

```bash
ip -br address
sudo ss -lntup
sudo systemctl status nginx opla-suricata --no-pager
sudo journalctl -u opla-suricata -n 30 --no-pager
exit
```

After vm-resume, connection refused may mean SSH has not started. Check QEMU and retry ready; do not create another lab merely to wait. On the host:

```bash
lab_id="${LAB_DIR##*/}"
sudo systemctl show "qemu-$lab_id-victim.service" -p ActiveState -p SubState -p MainPID
make console VM=victim
```

The console connects to an existing instance, not another VM.

## XDP and policy changes

```bash
make xdp-stats
bash bin/source-map.sh
bash bin/xdp-scan-policy.sh observe
```

Choose one policy mode; running observe/block/off in sequence leaves off. `xdp-deploy` copies sources/collector without replacing the attached program. Changing a shell build variable does not change the old object. For a deliberate reload:

```bash
make monitoring-stop
make xdp-unload
make xdp-all THRESHOLD=100 MAX_SOURCES=4096
bash bin/xdp-scan-policy.sh block
make monitoring-start
```

This interrupts protection and recreates maps. Counters belong to different epochs across reload. Trust addresses come from the selected lab; preserve management access before blocking.

Inside victim:

```bash
sudo ip -details link show dev ens3
sudo bpftool net show
sudo bpftool prog show pinned /sys/fs/bpf/opla/program
sudo bpftool map show
sudo bpftool -p map dump pinned /sys/fs/bpf/opla/maps/xdp_stats
sudo bpftool -p map dump pinned /sys/fs/bpf/opla/maps/syn_windows
```

Aggregate per-CPU values. Scan drops are already included in total drops. Malformed headers need not increment SYN counters. Source window age is not last-seen time. `map_full` needs investigation; no automatic state GC exists.

## Suricata, HTTP and passive detection

The following are alternative commands, not a sequence to run unchanged:

```bash
make ids-status
make ids
make ips
make ids-off
bash bin/scan-detector.sh status
```

Stopping an IPS engine while leaving NFQUEUE rules can close the HTTP path. Use ids-off for orderly removal of the owned queue.

```bash
bash bin/security-http.sh apply
bash bin/security-http-test.sh
make ids-test
```

HTTP 000 alone proves a timeout, not IPS enforcement. Correlate EVE SID, blocked-decision deltas and a normal HTTP 200. Historical parse errors should be compared by delta; missing capture.kernel_drops in NFQUEUE stats is not malformed JSON.

Native XDP can drop before AF_PACKET; the passive detector need not see blocked probes. ARP discovery and scans below threshold are allowed. Nmap closed means an RST; filtered does not identify which security mechanism caused the missing response.

## Monitoring and email

```bash
make monitoring-stop
python3 monitoring/diagnose.py --lab "$LAB_DIR"
make monitoring-start
lab_id="${LAB_DIR##*/}"
journalctl --user -u "opla-monitor-$lab_id.service" -n 40 --no-pager
python3 monitoring/alert_delivery.py status
journalctl --user -u opla-alerts.service -n 30 --no-pager
```

Collector and diagnostics share a lock. Old Latest data values do not prove fresh collection; inspect timestamps and heartbeat. SMTP acceptance is distinct from inbox delivery. Queue totals are not network attack totals.

## Docker and CI networking

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
docker network inspect opla-ci-bridge
sudo /usr/sbin/nft list chain inet filter opla_ci_forward
sudo systemctl show opla-ci-firewall.service -p Result -p ExecMainStatus
sudo systemctl list-timers opla-ci-firewall.timer --no-pager
```

The CI exception applies to its own bridge, not the VM lab. A Docker-table accept does not override another base-chain drop. Do not flush the firewall for troubleshooting. The CI helper does not reconstruct all deleted Docker tables. GitHub hosted runners need neither the local Tor proxy nor the separate GitLab Runner toolkit.
