# Metrics catalogue and data sources

[Русский](metrics-catalog.md) · **English**

I document the metrics against source code so that the manual and the implementation agree. These counts describe configuration, **not proof that objects exist or have fresh data in a running Zabbix instance**.

`monitoring/catalog.py` defines **34 primary items and 15 dependent rates (49 items total)**. `monitoring/setup.py` defines **23 triggers, 5 graphs and 5 dashboard pages**.

## Primary items

| Zabbix key | Type | Unit | Meaning |
|---|---|---|---|
| `xdp.scan_mode` | Numeric unsigned | — | XDP scan policy: off=0, observe=1, block=2 |
| `xdp.scan_events` | Numeric unsigned | — | Distinct-port threshold crossings |
| `xdp.scan_drop` | Numeric unsigned | — | New SYNs blocked by scan policy |
| `scan.enabled` | Numeric unsigned | — | Passive scan detector configured (0/1) |
| `scan.up` | Numeric unsigned | — | Detector heartbeat (0/1) |
| `scan.active` | Numeric unsigned | — | Sources exceeding distinct-port threshold |
| `scan.alerts` | Numeric unsigned | — | Scan threshold crossings |
| `scan.capture_drops` | Numeric unsigned | — | Passive capture socket drops |
| `scan.evictions` | Numeric unsigned | — | Passive detector state evictions |
| `scan.details` | Text | — | Last source and destination in scan detection |
| `ids.enabled` | Numeric unsigned | — | Suricata configured (0/1) |
| `ids.up` | Numeric unsigned | — | Suricata running (0/1) |
| `ids.alerts` | Numeric unsigned | — | Suricata alerts |
| `ids.blocked` | Numeric unsigned | — | Suricata blocking decisions |
| `ids.parse_errors` | Numeric unsigned | — | EVE parsing errors |
| `ids.kernel_drops` | Numeric unsigned | — | Capture drops in current engine epoch |
| `xdp.loaded` | Numeric unsigned | — | XDP attached (0/1) |
| `xdp.mode` | Character | — | Attachment mode |
| `xdp.syn` | Numeric unsigned | — | Initial SYNs observed |
| `xdp.pass` | Numeric unsigned | — | SYNs allowed |
| `xdp.drop` | Numeric unsigned | — | SYNs blocked |
| `xdp.map_full` | Numeric unsigned | — | Source-map capacity drops |
| `xdp.fragment_drop` | Numeric unsigned | — | IPv4 TCP fragment drops |
| `xdp.events` | Log | — | Security interval events |
| `net.rx_packets` | Numeric unsigned | — | ens3 driver RX packets |
| `net.rx_bytes` | Numeric unsigned | B | ens3 driver RX bytes |
| `http.available` | Numeric unsigned | — | HTTP JSON log readable (0/1) |
| `http.requests` | Numeric unsigned | — | Requests in HTTP JSON log |
| `http.limited` | Numeric unsigned | — | Requests rejected by nginx limiter |
| `http.errors5xx` | Numeric unsigned | — | HTTP 5xx responses |
| `http.parse_errors` | Numeric unsigned | — | Invalid HTTP log records |
| `http.up` | Numeric unsigned | — | Local HTTP probe returns 200 (0/1) |
| `http.status` | Numeric unsigned | — | Local HTTP response code |
| `http.latency` | Numeric unsigned | us | Local HTTP probe duration |

## Dependent rates

| Zabbix key | Master item | Unit |
|---|---|---|
| `xdp.scan_events.rate` | `xdp.scan_events` | pps |
| `xdp.scan_drop.rate` | `xdp.scan_drop` | pps |
| `ids.alerts.rate` | `ids.alerts` | pps |
| `ids.blocked.rate` | `ids.blocked` | pps |
| `ids.kernel_drops.rate` | `ids.kernel_drops` | pps |
| `xdp.syn.rate` | `xdp.syn` | pps |
| `xdp.pass.rate` | `xdp.pass` | pps |
| `xdp.drop.rate` | `xdp.drop` | pps |
| `xdp.map_full.rate` | `xdp.map_full` | pps |
| `xdp.fragment_drop.rate` | `xdp.fragment_drop` | pps |
| `net.rx_packets.rate` | `net.rx_packets` | pps |
| `net.rx_bytes.rate` | `net.rx_bytes` | Bps |
| `http.requests.rate` | `http.requests` | rps |
| `http.limited.rate` | `http.limited` | rps |
| `http.errors5xx.rate` | `http.errors5xx` | rps |

## Interpretation

Zabbix computes dependent rates using consecutive cumulative values (`Change per second`). A reset or missing sample requires a new valid measurement pair. `xdp.loaded=1` confirms attachment to the monitored interface, not HTTP availability or the health of every sensor. `http.up` is a local victim probe; check the independent client separately. `scan.*` refers to the passive detector, while `ids.*` refers to Suricata.

No fresh value means unknown telemetry state, not zero load. Driver `net.rx_*` counters do not necessarily include all frames dropped by native XDP. `ids.kernel_drops` is relative to the capture-engine epoch, not a universal packet-loss metric. A new metric requires coordinated changes to its source, catalogue, transport, tests and documentation.
