# Threat model and applicability boundaries

[Русский](security-model.md) · **English**

I prepared this model for the OPLA teaching lab. Its scope is the availability of a test HTTP service and the reliability of experiment results, not industrial infrastructure or real customer-data protection.

## 1 Assets

Primary assets are test HTTP availability and the ability to explain filter behavior with trustworthy evidence. Other assets include SSH keys, the KVM host, lab state, database credentials and test results. No certified OS security or production-data confidentiality is claimed.

## 2 Adversary and trust

In the baseline experiment, attacker controls its own VM and sends traffic to victim within the /29. Host administrators, source code, orchestration keys and monitoring configuration are trusted. Malicious host root is out of scope: it could alter BPF maps, executables, logs and the database. Guest `student` NOPASSWD privileges are an explicit educational assumption. VM isolation does not establish resistance to hypervisor escape. Docker socket and group membership grant broad host privileges. Never publish local keys, passwords or raw dumps without review.

## 3 Threats and mitigations

| Threat | Implemented measure | Limitation / validation |
|---|---|---|
| Excessive initial SYNs | XDP per-IP fixed window | NAT and distributed IPs; verify Δdrop and independent client |
| Invalid lengths / IPv4 TCP fragments | Bounds checks and explicit fragment DROP | Some drops are not SYN drops; validate in kernel |
| Concurrent window updates | `bpf_spin_lock` | Mock tests do not prove all race-free behavior |
| Source-map exhaustion | Bounded map, fail-closed for new SYN, `map_full` | Legitimate new sources can be denied |
| HTTP load within a connection | nginx `limit_req` and timeouts | Not a WAF; clients sharing IP share quota |
| Telemetry loss | Format checks, accepted counts and no-data alert | No guarantee of every log/event delivery |
| Injected `state.env` | Data parsing and trusted-path validation | Trusted root can still change state |
| Traffic escaping the lab | No default route and scoped nftables | Independent forwarding test remains necessary |
| DB password / key leakage | `.gitignore`, getpass and local binds | Audit Git history and external archives separately |

## 4 L2–L7 coverage

L2: no dedicated ARP/MAC anti-spoofing; VLAN parsing is not comprehensive VLAN defense. L3/L4: the base SYN rule limits IPv4 initial SYNs and drops fragmented TCP; it does not rate-limit UDP, ICMP, IPv6 or ACK. Port scanning has a separate XDP policy. L5/L6: TLS is not deployed in the basic lab. L7: nginx rate limiting and HTTP telemetry are implemented; SQLi/XSS protection requires application controls or a separately validated WAF.

The public implementation includes separate Suricata IDS/IPS scenarios and IDS/scan telemetry sources, but their live state must be checked independently. An alert is not automatically a block. HTTP/UDP/ACK control traffic does not prove universal attack protection.

## 5 Operational limitations

There are no cryptographic telemetry signatures, chained event hashes or defenses against a malicious database administrator. Maximum pps, latency overhead, automatic full reboot recovery and comprehensive PCAP-to-DB capture have not been established. Long-term deployment requires HTTP JSON log rotation, disk quotas, narrower agent privileges and dedicated review of TLS, authentication, secrets, patching, least privilege and independent verification.
