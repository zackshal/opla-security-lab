# Automated dashboard, HTTP protection and L2–L7 boundaries

[Русский](dashboard-and-layers.md) · **English**

This document describes the OPLA observability layer: XDP metrics, IDS/IPS events and HTTP-service health. I distinguish measurements actually observed from values defined in configuration.

## Meaning of XDP attached

`XDP attached` is a Boolean for one program on victim's ens3: 1 means attached and 0 means detached. It is not a count of protection systems. Interface, HTTP and XDP metrics have distinct origins.

## Deploy on an existing lab

From the project root on the host:

```bash
make check
export LAB_DIR="$(python3 bin/state.py --latest)"
make ready
make monitoring-up
bash bin/observability-up.sh
```

Change the default Zabbix password first. The observability script stops collection, installs the nginx policy with `nginx -t`/reload, deploys `collect.py`, prompts for the API password, provisions objects and restarts collection. It does not recreate VMs or modify their backing images. Select `LAB_DIR` explicitly when multiple labs exist and repeat configuration for a new lab. The managed dashboard is replaced during provisioning; clone manually edited dashboards under another name.

## Provisioned objects

The source code defines **49 items (34 inputs, 15 dependent rates), 23 triggers, 5 graphs and 5 dashboard pages**. Confirm actual objects and fresh data in the running Zabbix API.

| Page | Data |
|---|---|
| XDP and events | Attachment/mode, SYN/pass/drop, scan policy, events and Problems |
| HTTP protection | Local availability/status/latency, JSON access log, 429/5xx and rates |
| Interface traffic | Driver RX packets/bytes, pps/Bps and interface graphs |
| IDS and IPS | Suricata enabled/up, alerts/blocked, EVE errors and capture drops |
| Port-scan detection | Passive detector health, active sources, alerts, evictions and details |

Use Data collection → Hosts → current `opla-ID` → Items and Latest data with old filters cleared. Inspect fresh `xdp.*`, `http.*`, `net.*`, `ids.*` and `scan.*` values and recent graphs. HTTP status 0 means the local probe received no HTTP response. The probe runs on victim against `127.0.0.1:80`: it does not test attacker→victim or client→victim connectivity. It generates a small amount of traffic counted by HTTP metrics. `http.latency` uses microseconds, not milliseconds. Driver `net.rx_*` counters may omit packets dropped before the normal path by native XDP.

Source definitions and wire keys live in `monitoring/catalog.py`. A new Zabbix item without a real source measures nothing.

## Detection rules and interpretation

| Condition | Meaning |
|---|---|
| `attached=0` | XDP detached |
| No collector data for 60 seconds | Telemetry unavailable |
| `drop.rate` positive in 30 seconds | SYN dropping observed |
| `map_full.rate` positive | New source could not be inserted |
| `fragment_drop.rate` positive | Fragmented TCP dropped |
| `syn.rate>500` and `drop.rate>100` peaks | High SYN load with drops; peaks may be from different snapshots |
| JSON log missing | HTTP telemetry unavailable |
| `http.limited.rate` positive | nginx rate limiter rejected requests |
| `http.errors5xx.rate` positive | HTTP server errors observed |
| Increasing parse errors | JSON records failed parsing |
| Three unsuccessful local HTTP probes | Local HTTP unavailable |
| Three local HTTP probes over 500 ms | Local HTTP latency elevated |

A 30-second hold makes short bursts visible. Co-occurring peak rates do not establish per-packet correlation. Rate limiting does not establish malicious intent. Tune thresholds using normal traffic and false-positive analysis. Trigger policy is in `monitoring/policy.json` and can be reprovisioned with `make monitoring-configure`; XDP's `THRESHOLD` and nginx `limit_req` are separate enforcement settings.

## Actual nginx L7 policy

`/etc/nginx/conf.d/opla-l7.conf` configures 5 requests/s per client IP, `burst=10`, `nodelay`, HTTP 429 for rejected requests, 10-second header/body/send timeouts, a 1 MiB body limit and a dedicated structured JSON log (status, source, method, URI, duration and `limit_req` result).

These educational limits may reject legitimate clients or multiple users behind NAT. This is not SQLi/XSS defense or a WAF. Inherited `limit_req` and `access_log` settings in other server/location blocks can change behavior; inspect effective `nginx -T` after local changes.

The collector counts `limit_req=REJECTED`, not every HTTP 429. It incrementally reads complete JSON lines with a cursor and lock under `/var/lib/opla-telemetry`, persists cumulative counters, and handles inode changes and truncation. It reads no more than 1 MiB per poll. An unread tail of a rotated file can be lost; this is aggregate telemetry, not guaranteed log delivery. Removing its state file can cause recounting. Configure explicit JSON-log rotation for longer operation. Zabbix receives aggregates and selected events, not every access-log row; inspect per-request details in the victim log.

## Experiments and expected evidence

### A. SYN and XDP

```bash
make xdp-stats
bash bin/traffic-scenario.sh syn
```

Check SYN/drop deltas, the XDP dashboard and the drop event. Use the last **successfully loaded** threshold, not the requested threshold of a failed reload.

### B. HTTP with persistent connections

```bash
bash bin/security-http-test.sh
```

The generator sends 200 requests using four workers with connection reuse. Record HTTP 200/429, `http.requests`, `http.limited`, trigger history and `reports/scenario-http-burst-*`. Do not assume exact rejection counts. A transport error is not HTTP 429. In parallel, probe HTTP once per second from the independent client, which has a different source IP.

### C. Recovery after a burst

After more than 30 seconds, check that rates fall to zero, events recover, cumulative counters remain and the local HTTP probe returns 200.

### D. Collector outage

```bash
make monitoring-stop
# Wait more than 60 seconds and inspect the no-data event.
make monitoring-start
```

This is a controlled telemetry outage, not an attack. Verify fresh values and event recovery.

### E. Inspect logs and diagnostics

On the host:

```bash
export LAB_DIR="$(python3 bin/state.py --latest)"
lab_id="$(python3 bin/state.py "$LAB_DIR" LAB_ID)"
tail -n 3 "monitoring/runtime/$lab_id/events.jsonl"
journalctl --user -u "opla-monitor-$lab_id.service" -n 30 --no-pager
make ssh VM=victim
```

On victim:

```bash
sudo nginx -T
sudo tail -n 20 /var/log/nginx/opla-security.jsonl
sudo tail -n 20 /var/log/nginx/error.log
sudo bpftool prog show pinned /sys/fs/bpf/opla/program
exit
```

Stop the collector before `python3 monitoring/diagnose.py --lab "$LAB_DIR"` and restart it afterward. A healthy full input sample should report 34 ACCEPTED values; confirm actual output. Allow two fresh samples for dependent rates.

## L2–L7 coverage and tools

| Layer / scenario | Observation | Potential prevention | OPLA status |
|---|---|---|---|
| L2 ARP/MAC spoofing | `tcpdump -e -n arp`, `ip neigh`, arping | Bridge bindings, switch DAI | No automated ARP spoofing protection |
| L2 VLAN | Tagged-frame inspection, tcpdump | VLAN/port isolation | Parser handles up to two tags; not universal VLAN protection |
| L3 ICMP/fragments | hping3, tcpdump | Fragment policy and ICMP limits | IPv4 TCP fragments dropped; ICMP not rate-limited |
| L4 SYN | hping3, bpftool, `ss` | XDP per-IP limiter | Implemented and previously observed |
| L4 UDP/ACK | hping3, tcpdump | Separate ACL/limiter | Not blocked by base SYN policy |
| L4 port scanning | Bounded Nmap and Suricata | XDP scan observe/block policy, ACL | Separate XDP scan policy exists; validate selected mode |
| L5–L6 TLS | `openssl s_client`, curl | TLS termination policy | HTTPS not deployed in basic lab |
| L7 HTTP bursts | Keep-alive test and JSON log | nginx `limit_req`, HTTP 429 | Configured; individual runs require evidence |
| L7 SQLi/XSS | Test application and WAF audit log | Parameterized queries, output encoding, CRS | No general WAF or vulnerable test application included |

OSI layers are an aid to discussion, not independent packet paths. A prevention claim requires actual drop/reject evidence, not only an alert.

A bounded scan of the lab victim can use Nmap after installation on attacker, for example:

```bash
nmap -sT -Pn --max-rate 20 --max-retries 0 --host-timeout 20s -p 22,80,443 100.64.0.3
```

Replace the IP with the current state value. A closed port is not evidence of XDP blocking.

Suricata sample rules in `security/suricata/opla.rules` cover SYN, UDP and HTTP GET observations. Configure HOME_NET for the current /29, validate syntax (`suricata -T`) and test IDS versus IPS paths separately. Alert and drop are different actions; `detection_filter` is not an XDP rate limiter. The public collector includes IDS/scan sources, but live EVE ingestion and fresh Zabbix values must be verified. Isolated VMs have no Internet access, so installing additional tools may require a new prepared image and redeployment; do not modify a backing image while VMs are running.

## Database

The legacy XDP query is `monitoring/sql/inspect.sql`; the wider read-only query is `monitoring/sql/security-overview.sql`:

```bash
lab_id="$(python3 bin/state.py "$LAB_DIR" LAB_ID)"
docker compose --env-file monitoring/.env -f monitoring/compose.yaml exec -T db \
  psql -U zabbix -d zabbix -v "host_name=opla-$lab_id" \
  < monitoring/sql/security-overview.sql
```

The query reads latest values from the appropriate history tables: `history_uint`, `history`, `history_str` and `history_log`. It does not modify the database.

## Changes and rollback

Use a dedicated branch and Pull Request for public changes; do not replay the original feature commit. To remove the HTTP policy use `bash bin/security-http.sh remove` and inspect the nginx test/reload. For a wider rollback, stop the collector, remove the policy, revert the relevant change, redeploy XDP and reprovision monitoring. Old Zabbix items may remain after code rollback and should not be mistaken for an active policy.

## Evidence limits

Portable C/Python checks cover parsing, provisioning, widget mapping and HTTP-log collection. A local test run is not proof of a live Zabbix API, current nginx behavior, Suricata enforcement or kernel verifier acceptance on every host. For actual acceptance see the [protocol](run-protocol.en.md) and [acceptance matrix](acceptance.en.md). References: Zabbix 7.0 API, nginx rate-limiting/logging modules, Suricata IPS documentation and OWASP CRS.
