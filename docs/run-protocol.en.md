# Local validation protocol

[Русский](run-protocol.md) · **English**

Author: Zakhar Shalashov, fourth-year undergraduate, group BBBO-01-23. Revision: 25 October 2026. This protocol summarizes earlier terminal output and saved `reports/` artifacts. It explicitly distinguishes those observations from tests **not repeated on a clean lab for this revision**.

## 1 Repair history and current state

An initial victim cloud-init run failed because nginx was missing. After image preparation all three VMs reported `status: done`. A kernel verifier rejected `ip+total` pointer arithmetic; comparing the declared length with available packet bytes allowed native-mode loading while retaining TCP bounds checks.

Other fixes included iproute2 JSON `attached` array normalization, per-CPU/u64 decoding, portable C test execution on a `noexec` `/tmp`, and `/usr/sbin` in bpftool version collection. The working GitLab history was merged earlier and updated documentation was committed at `66a003a`. Public GitHub had a separate history (`bca6d66` when migration began). Moving files does not create new test evidence. Two HTTP bursts and some IDS/IPS scenarios have saved local reports, but cannot be generalized to all modes.

## 2 Recorded tests

| Check | Recorded observation | Scope |
|---|---|---|
| Earlier portable suite | 11 Python tests and C PASS | Passed on the user's host |
| Three VMs | Three cloud-init `status: done` | Guest preparation observed |
| Build and load | Clang compiled BPF; verifier accepted | Kernel test in that environment |
| XDP attachment | bpftool: ens3 driver, program ID 75, JIT | Native attachment observed; ID is temporary |
| BPF maps | `syn_windows` hash and per-CPU `xdp_stats` | Maps present and readable |
| Client HTTP | 60 responses 200; 0.000358–0.001373 s | Service reachable in recorded run |
| Historical Zabbix | 11 enabled items in PostgreSQL | Earlier XDP catalogue, not the 49-item current catalogue |
| Rate and event history | `history`/`history_log` contained a burst | XDP → collector → database observed |
| Updated portable suite | 92 Python tests (1 skipped) and C harness | Passed in working integration copy; **not rerun here on public GitHub** |

## 3 Traffic experiments

| Run / saved report | Δsyn | Δpass | Δdrop | Δmap_full | Δfragment_drop |
|---|---:|---:|---:|---:|---:|
| SYN, `scenario-syn-ynKwzUiD` | 2004 | 509 | 1495 | 0 | 0 |
| ACK, `scenario-ack-VVaLavIY` | 3 | 3 | 0 | 0 | 0 |
| UDP, `scenario-udp-q3JnTHNW` | 5 | 5 | 0 | 0 | 0 |
| ICMP, `scenario-icmp-2eOrvFM2` | 3 | 3 | 0 | 0 | 0 |
| HTTP, `scenario-http-29PcYpca` | 102 | 102 | 0 | 0 | 0 |
| SYN after reload, `scenario-syn-DiWk0wHX` | 2003 | 301 | 1702 | 0 | 0 |

The recorded generators exited with status 0. Background SSH/collector SYNs may contribute. In the first SYN run 509+1495=2004; in the last 301+1702=2003, with approximately 85.0% of **counted SYNs** dropped. This is not the fraction of all packets. An earlier `xdp-all THRESHOLD=100` failed because ens3 already had XDP; the failed command cannot establish the active threshold. Relate each run to the last successful attachment before comparing thresholds.

The UDP generator sent 1,000 packets and received 8 replies, while hping displayed 100% packet loss. That display does not prove UDP dropping by XDP: no UDP rate limiter exists in the base SYN code, and SYN-drop did not increase.

## 4 Direct PostgreSQL observations

For host `opla-lab-dIQidjYq`, at 24 October 2026 01:54:56 Europe/Moscow, the saved SQL output showed:

| Key | Value |
|---|---:|
| `xdp.loaded` | 1 |
| `xdp.syn` | 2112 |
| `xdp.pass` | 410 |
| `xdp.drop` | 1702 |
| `xdp.map_full` | 0 |
| `xdp.fragment_drop` | 0 |

At 01:54:38, `syn.rate=468`, `pass.rate=49.5`, `drop.rate=418.5` packets/s; 49.5+418.5=468. After the burst, cumulative drop remained 1702 while `drop.rate` became zero. Snapshots were recorded at 01:54:36 and 01:54:38, with a `diagnostic_probe` at 01:51:31. nginx access-log lines showed HTTP 200 from attacker `100.64.0.2` in the control HTTP run; they are not logs of SYNs dropped before HTTP. Guest UTC versus SQL Europe/Moscow explains a three-hour display difference without necessarily implying clock drift.

## 5 Missing primary evidence

| Acceptance check | Required evidence | Status |
|---|---|---|
| Zabbix 49 items / 23 triggers / 5 pages | Live API, 34 ACCEPTED inputs, fresh data | Not confirmed live; counts from code |
| nginx HTTP limiting | 200/429, `http.limited`, client availability | Two bursts saved; independent-client correlation not attached |
| Trigger recovery | Problems history and recovery after hold | Not supplied |
| Collector outage over 60 s | No-data and subsequent recovery | Not supplied |
| Isolation with temporary default route | Actual forwarding blocked | Not supplied |
| Map capacity and fragmented packets in kernel | Live packet tests and metrics | Not supplied; portable tests exist |
| No XDP / thresholds 100 and 200 | Same workload with explicit conditions | Complete comparable series not supplied |
| Clean installation | End-to-end from scratch without manual fixes | Not established |

The basic XDP path and selected HTTP/IDS scenarios have local evidence. Full acceptance against the assignment has not been established by a clean deployment and complete experimental cycle.

## 6 Saved HTTP and IDS/IPS results

These values are **from retained `reports/` files**, not from a new run.

| Scenario | Time (Europe/Moscow) | HTTP 200 / 429 | Δ`http.requests` | Δ`http.limited` | Local check |
|---|---|---|---:|---:|---|
| `scenario-http-burst-r2z7cPoV` | 24 Oct 2026 02:14:25 | 11 / 189 | 201 | 189 | `http.up=1`, `http.status=200` before and after |
| `scenario-http-burst-uguWdSla` | 24 Oct 2026 13:18:55 | 11 / 189 | 201 | 189 | `http.up=1`, `http.status=200` before and after |

Each generator reported 200 requests using four connections. `http.requests=201` includes an additional local control probe, not a generator-count discrepancy. HTTP 429 and the matching `http.limited` delta demonstrate nginx limiting in these runs, but do not complete independent-client or clean-installation acceptance.

Saved `ids-acceptance-D111swwj` data recorded Δ`ids.alerts=2`, Δ`ids.blocked=1`, control HTTP 200 and a marked curl request ending with exit code 28 (timeout). This is consistent with IPS behavior, but without a primary EVE event (SID and precise request timestamp), causality of that particular timeout cannot be established. `ids.parse_errors=24` in both snapshots is a cumulative count with delta zero.

## 7 Evidence limitations

Do not replace acceptance checks A1/A4/A8/A9/A11/A12 with command descriptions, static tests or a demonstration video. The compact archive did not contain a PCAP or prepared image, so their hashes and contents were not independently confirmed. Public evidence should preserve provenance and omit private raw logs.
