# Components and protection boundaries

[Русский](architecture.md) · **English**

This map describes the current source tree. Use the [README](../README.md) for startup, [operations](operations.en.md) for diagnostics and the [acceptance matrix](acceptance.en.md) for verification criteria.

## Components

| Area | Source | Responsibility and boundary |
|---|---|---|
| Lab | [create-lab.sh](../bin/create-lab.sh), [state.py](../bin/state.py) | Three QEMU roles and validated state for the selected LAB_DIR; state is data, not shell code |
| Packet protection | [XDP C](../xdp/xdp_ddos_protect.c), [scan policy](../xdp/scan-policy.py) | Header validation, SYN window and distinct-port scan policy; no HTTP analysis or TLS decryption |
| IDS/IPS | [Suricata wrapper](../bin/suricata.sh), [configuration](../security/suricata/) | AF_PACKET IDS or the selected HTTP NFQUEUE IPS path; each mode needs its own evidence |
| HTTP | [HTTP policy](../bin/security-http.sh) | nginx rate limiting and structured access logs; nginx alone is not a general WAF |
| Telemetry | [collector](../xdp/collect.py), [bridge](../monitoring/bridge.py), [catalogue](../monitoring/catalog.py) | BPF, sysfs and logs have different sources and counter epochs; Zabbix delivery does not replace a source PCAP |
| Passive detection | [scan detector](../bin/scan-detector.sh) | Scan observation; native XDP may discard traffic before a passive detector receives it |
| Notifications | [queue and delivery](../monitoring/alert_delivery.py) | A separate delivery lifecycle; SMTP acceptance does not prove inbox delivery |
| Recovery | [QMP snapshots](../bin/vm-state.py), [disk copies](../bin/vm-disk.py) | Per-VM state and portable disk copies are different operations; database backup is separate |
| CI and delivery | [CI](../ci/README.en.md), [deployment](deployment.en.md) | Portable/configuration checks and BPF packaging; compilation does not prove live attachment or target acceptance |

## Observation path

Native XDP decides before the normal network path. A SYN dropped there produces no HTTP access log. Suricata IDS observes traffic available to its capture path; NFQUEUE IPS only affects the configured path. nginx handles allowed HTTP requests, while the independent client checks the external result.

The collector connects BPF counters, sysfs and logs to Zabbix. `xdp.scan_drop` is included in `drop`; adding them as independent losses double-counts packets. Program reload and interface recreation require counter-epoch handling.

The current [catalogue](../monitoring/catalog.py) defines 34 inputs and 15 dependent rates. These counts describe provisioning code, not fresh data on a running dashboard. Check heartbeat, timestamps and actual API objects; the historical 28-item description is not the current catalogue.

## Trust and data

The host and administrative accounts are trusted. Validate isolation for the selected LAB_ID through routes, scoped firewall rules and network probes. Do not clear the entire nft ruleset or replace an unknown XDP program to make a test pass.

Runtime data, mail credentials, private inventory, SSH keys, disks and raw logs are separate from source code. See [data lifecycle](data-lifecycle.en.md) and [backup/restore](backup-restore.en.md). Public Git history has already been prepared: [do not reimport the old branch](git-history.en.md).
