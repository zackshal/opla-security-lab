# Laboratory manual: observable protection of a Linux HTTP service

[Русский](methodology.md) · **English**

Practical assignment for the course “Detection, prevention and mitigation of computer attacks.”

Author and developer: Zakhar Shalashov, fourth-year Information Security bachelor's student, group BBBO-01-23, RTU MIREA. Moscow, 2026. Revision: 25 October 2026.

## 1 Purpose and learning outcomes

I designed this laboratory to connect network load, a protection decision and independently verifiable service behavior. The setup consists of three QEMU/KVM VMs: `attacker`, `victim` and `client`. Students investigate an eBPF/XDP IPv4 SYN limiter, collect telemetry in Zabbix and compare packet counters with HTTP availability. An additional nginx keep-alive workload separates application-layer rate limiting from SYN filtering.

The objectives are to install the tools, verify network isolation, inspect and build the C program, run identical bounded workloads, collect evidence, interpret results and prepare a reproducible report. TCP/IP, Linux shell and SSH fundamentals are assumed. A high packet rate is an indicator, not proof of malicious intent. Run tests only in the isolated laboratory network.

## 2 Theory

### 2.1 TCP and SYN flooding

TCP starts with SYN, SYN+ACK and ACK. Incomplete handshakes can consume SYN-RECV state and server resources. The outcome depends on SYN cookies, queues, operating-system settings, the service and traffic-generator capacity; a small test may not make HTTP unavailable.

The basic filter counts only IPv4/TCP packets with SYN=1 and ACK=0. Each source IP has a fixed window; SYNs above `THRESHOLD` within that window are dropped. ACK, UDP, ICMP and IPv6 are not inspected by this particular SYN policy, which does not make them intrinsically safe. The windows are per source, not aligned to a universal second. A burst may cross a window boundary. Clients behind one NAT share an IP budget, and distributed sources can evade a simple per-IP limit.

### 2.2 eBPF/XDP and the verifier

XDP executes a BPF program on received frames. Native XDP runs in a supported driver before the ordinary skb path; generic XDP runs later. Compilation and attachment are separate from successful verification and loading. The kernel verifier checks memory accesses, packet bounds, register types and permitted helpers. A previously observed `ip+total` verifier rejection was addressed with an explicit check against available packet bytes while preserving TCP bounds checks.

The `syn_windows` hash map holds at most 1,024 source addresses. A BPF spin lock protects window count and start time across CPUs. The per-CPU `xdp_stats` array holds cumulative counters that the collector sums. A single fixed-window count is not a reliable cumulative traffic rate.

### 2.3 HTTP rate limiting

A persistent TCP connection can carry many HTTP requests, so HTTP request counts and SYN counts are different. The teaching nginx policy uses `limit_req`: 5 requests per second per client IP, `burst=10`, and HTTP 429 on rejection. Timeouts and body-size limits address some resource-exhaustion paths, but are not a WAF. SQL injection and XSS require application-level defenses such as parameterized queries, output encoding and appropriate independent testing.

### 2.4 Detection, prevention and telemetry

XDP_DROP and nginx `limit_req` enforce decisions; Zabbix records metrics and evaluates triggers. A Zabbix trigger does not change a packet filter. A Suricata alert does not prove blocking unless the IPS path is enabled and verified. Rates use differences between cumulative measurements divided by elapsed time. Counter resets and missing samples must not be reported as negative traffic or zero load.

Three distinct pieces of evidence matter: the generator sent traffic, the filter made a decision, and an independent client received the service. Neither HTTP access logs nor drop graphs alone establish all three.

## 3 Topology and requirements

![Figure 1 — Laboratory topology and trust boundaries](figures/topology.svg)

| Node | Example IP | Role | Planning resources |
|---|---|---|---|
| Host | 100.64.0.1 | Bridge, QEMU, SSH collector and containers | KVM, 12 GiB RAM and 30 GiB disk reserved |
| attacker | 100.64.0.2 | hping3, curl and tcpdump | 1 vCPU, 1 GiB RAM |
| victim | 100.64.0.3 | Linux XDP and nginx | 2 vCPU, 2 GiB RAM |
| client | 100.64.0.4 | Independent HTTP checks | 1 vCPU, 512 MiB RAM |

These are planning figures, not measured minimums. Scripts choose a free /29 from 100.64.0.0/10; use actual addresses from `state.env`. VM state and overlays live under `/var/lib/opla/lab-ID`; the base qcow2 is under `images/` and PostgreSQL uses a separate Docker volume. The host installer targets Debian 12. A host observed with Debian 13 packages is not proof of a clean Debian 13 installation. See [software and versions](software.en.md).

## 4 Prepare the environment

### Step 1 — Prepare a dedicated Debian host

```bash
sudo ./bin/install-host.sh
ls -l /dev/kvm
docker compose version
```

Check KVM and Compose v2. Docker-group membership confers powerful host privileges. Prepare an SSH Ed25519 key if needed (`ssh-keygen -t ed25519`) but never commit the private key.

### Step 2 — Download and prepare images

```bash
make bootstrap
LIBGUESTFS_BACKEND=direct make image
```

`bootstrap` downloads a Debian cloud image and records hashes; image preparation installs nginx, Clang, libbpf, bpftool, hping3, curl and tcpdump before isolated execution. Do not modify the backing image of running VMs. Record source URLs, hashes and package versions; a `latest` download is not an immutable environment.

### Step 3 — Start the lab

```bash
make up
export LAB_DIR="$(python3 bin/state.py --latest)"
make ready
python3 bin/state.py "$LAB_DIR" VICTIM_IP
```

Wait for all three cloud-init statuses to become `done`. An early SSH refusal is not a security-test result. Investigate guest `/var/log/cloud-init-output.log` on errors. Run Make targets from the repository root on the host; leave an SSH session with `exit`.

## 5 Verify isolation

### Step 4 — Inspect the selected network

```bash
python3 bin/state.py "$LAB_DIR" LAB_ID
python3 bin/state.py "$LAB_DIR" BRIDGE
sudo nft list ruleset
make ssh VM=victim
ip -4 addr show dev ens3
ip route
exit
```

Expect the selected /29 and no default route. The scoped nftables rules should block forwarding through the host and unauthorized new guest-to-host connections. Save actual output; the topology drawing alone is not evidence. A separate forwarding test can temporarily add a default route through the lab gateway and probe a known reachable external test service. Remove the temporary route afterward. The available evidence does not establish that this forwarding test was completed.

## 6 Load and observe XDP

![Figure 2 — Frame parsing and XDP decision](figures/packet-path.svg)

### Step 5 — Build, load and inspect

```bash
make check
make xdp-all THRESHOLD=100
make xdp-stats
make versions
make ssh VM=victim
sudo bpftool net show
sudo bpftool prog show pinned /sys/fs/bpf/opla/program
sudo bpftool -p map dump pinned /sys/fs/bpf/opla/maps/xdp_stats
exit
```

Verify successful Clang build, kernel verifier, attachment mode, JIT and maps. Program IDs are ephemeral. If ens3 already has XDP attached, record the current state, use `make xdp-unload` and then load again. A failed reload does not change the active threshold. Sum per-CPU values rather than treating each CPU slot as the total.

### Step 6 — Run a bounded SYN experiment with a separate client

From one host terminal, run `make ssh VM=client`; inside the client, using the actual victim IP:

```bash
for i in $(seq 1 60); do
  printf '%s ' "$(date -Is)"
  curl --max-time 3 -sS -o /dev/null \
    -w 'HTTP=%{http_code} time=%{time_total}s\n' http://100.64.0.3/
  sleep 1
done
```

At the same time, from a second host terminal:

```bash
bash bin/traffic-scenario.sh syn
```

Retain before/after counters, generator status and timestamps from `reports/scenario-syn-*`. The independent client has its own source IP; account for background SSH SYNs.

### Step 7 — Compare policies fairly

First run the same workload with XDP unloaded, then after successful loads with `THRESHOLD=100` and `THRESHOLD=200`. Compare only measurements from each separate counter epoch. If HTTP stays available even without filtering, the result demonstrates SYN dropping, not necessarily improved service availability. Do not increase load beyond the authorized isolated lab merely to induce a failure.

## 7 Zabbix and application protection

### Step 8 — Configure monitoring

```bash
make monitoring-up
bash bin/observability-up.sh
```

Open `http://127.0.0.1:8080`, wait for PostgreSQL and change the default Zabbix password. The observability script configures nginx, deploys the collector and provisions the catalogue: 49 items (34 input and 15 dependent), 23 triggers, 5 graphs and 5 dashboard pages. These are code-defined objects; verify actual API state and fresh values. The managed dashboard may be replaced, so clone any manually edited copy first. Reset Latest data filters and select the current lab host.

### Step 9 — Test HTTP limiting

```bash
bash bin/security-http-test.sh
```

The test sends 200 requests from four workers over reused connections. Record HTTP 200/429 counts, changes in `http.limited` and trigger history; do not assume a fixed rejection count. Continue probing HTTP from the separate client. The local `http.up` metric runs on victim and does not prove client-to-victim connectivity.

### Step 10 — Verify database delivery

```bash
make monitoring-stop
python3 monitoring/diagnose.py --lab "$LAB_DIR"
make monitoring-start
lab_id="$(python3 bin/state.py "$LAB_DIR" LAB_ID)"
docker compose --env-file monitoring/.env -f monitoring/compose.yaml exec -T db \
  psql -U zabbix -d zabbix -v "host_name=opla-$lab_id" \
  < monitoring/sql/security-overview.sql
```

Expect up to 34 accepted input values when the corresponding sources are healthy; confirm real output. Different value types are stored in `history_uint`, `history`, `history_str` and `history_log`. The query is read-only. The database stores snapshots rather than every packet.

### Step 11 — Test missing telemetry and recovery

Stop the collector for more than 60 seconds, check the Zabbix no-data event, restart it and verify that timestamps resume and the event recovers. Save the Problems history, not just the current open-event view.

## 8 Additional bounded scenarios and troubleshooting

```bash
bash bin/traffic-scenario.sh ack
bash bin/traffic-scenario.sh udp
bash bin/traffic-scenario.sh icmp
bash bin/traffic-scenario.sh http
```

These experiments reveal the SYN filter's limits. Lack of UDP responses does not prove XDP_DROP. Use tcpdump at a meaningful capture point, considering native XDP's position. Save PCAP before `make down`.

| Symptom | Action |
|---|---|
| Unknown Make target | Return to repository root |
| bpftool missing | Check guest package and `/usr/sbin` in PATH |
| Guest not ready | Check `cloud-init status --long` and output log |
| ens3 already has XDP | Record state, unload, then reload |
| Collector already running | Stop it before running diagnostics |
| Partial Zabbix acceptance | Check individual keys, catalogue and configuration cache |
| Stale dashboard | Select correct LAB_ID and inspect timestamps |
| `nginx -t` fails | Inspect error; deployment script restores its configuration |
| Guest and SQL differ by 3 hours | Compare UTC with Europe/Moscow; check `date -Is` |

The [layer coverage matrix](dashboard-and-layers.en.md) describes other scenarios; it is not a claim of universal L2–L7 protection. TLS and ARP spoofing are not addressed by a dedicated policy in the basic lab.

## 9 Student report contents

Include the objective, topology with actual IPs, versions and image hash, isolation evidence, successful build/load commands, bounded workloads, before/after counters, client HTTP results, Zabbix graphs/events, database query, recovery experiment, self-check answers and a justified conclusion. Record commit, configuration, timestamp and observation point for each run. Do not combine values from unrelated executions.

## 10 Assessment and appendices

Five exercises, self-check questions and a test are in [assessment materials](fos.en.md). The answer key is distributed privately to the instructor and is not part of this public repository. See [sources](sources.en.md), `cloud-init/`, `security/`, `monitoring/`, `xdp/`, `bin/`, `tests/` and `docs/figures/`. Publish only reviewed, non-sensitive evidence. Public PDFs are generated from Markdown into `release-artifacts/public/` and excluded from Git.
