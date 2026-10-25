# OPLA portfolio: Linux component security

[Русский](portfolio.md) · **English**

I developed OPLA as a fourth-year undergraduate Information Security project. This page summarizes work I can demonstrate through source code, configuration and retained experimental evidence.

## Short résumé description

**OPLA laboratory project: eBPF/XDP, virtualization and Linux security observability.** Designed and debugged an isolated three-VM Debian QEMU/KVM lab, an IPv4 TCP SYN limiter in XDP and a Python/Zabbix/PostgreSQL telemetry pipeline. Investigated a kernel verifier rejection, corrected packet-length validation, and observed native attachment/JIT, BPF maps and consistency between counters and database records. Documented the architecture, trust boundaries, bounded scenarios and applicability limits.

This is educational work, not a commercial deployment. In an interview I should be able to explain the design and show corresponding source code and evidence. Tools used during preparation do not justify rewriting others' Git authorship or claiming unperformed tests.

## Detailed experience

- Designed attacker/victim/client separation, image preparation, overlays and state storage; assessed SSH administration, Docker privileges and the virtual network boundary.
- Worked with C, Clang, the BPF verifier, bpftool, per-CPU maps, spin locks and native/generic XDP; resolved a specific IPv4 packet-length verifier issue.
- Connected SYN generation, filter decisions, independent HTTP availability and Zabbix history. One recorded run had 2,003 SYNs, 301 PASS and 1,702 DROP.
- Automated monitoring provisioning with a 49-item catalogue, nginx HTTP rate limiting and a keep-alive test. Some local HTTP/IDS scenarios have retained evidence, but full live acceptance and clean installation remain unverified.
- Prepared portable parser/telemetry tests, laboratory materials, acceptance protocol and a publication plan that preserves Git history.

## Relevance to an Astra Linux security role

The target skill set includes Linux component interactions, protection mechanisms, architecture and attack-surface analysis. **Tests here were run on Debian, not Astra Linux Special Edition.** This project does not establish experience configuring Astra-specific mandatory controls, PAM/Kerberos or certification testing.

| Competency | Interview demonstration |
|---|---|
| Linux internals | XDP execution, verifier, JIT/BTF versus CO-RE |
| Virtualization | Backing image/overlay, cloud-init seed, bridge, KVM, systemd |
| Security architecture | Trusted host, guest root, SSH, Docker, local ports and data flows |
| Troubleshooting | Verifier failure, PATH, noexec, iproute2 JSON and counter/DB reconciliation |
| Client/server software | HTTP keep-alive, limiting, collector, Zabbix API and PostgreSQL |
| Documentation | Diagrams, ADRs, threat model, limitations and reproducible evidence |

## Seven-to-ten-minute demonstration

1. Show the three roles, trusted host and lack of an external route.
2. Open the C parser and explain bounds checks, the fixed window and maps.
3. Inspect native/JIT state with bpftool and run a bounded SYN scenario.
4. Compare before/after counters and client HTTP, accounting for background SYNs.
5. Find the same period in Zabbix and SQL: cumulative drop versus `drop.rate`.
6. If verified in the current environment, show HTTP 200/429 over persistent connections.
7. Conclude with NAT, fixed-window and capacity limits and the absence of universal L2–L7 protection.
