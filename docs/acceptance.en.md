# Checks and evidence matrix

[Русский](acceptance.md) · **English**

This matrix defines criteria; it does not announce a new successful run. The [README](../README.md) records observed results and limitations; [versions](versions.en.md) records the environment. Another project or an earlier commit cannot establish acceptance for this revision.

| Area | Check | Sufficient evidence |
|---|---|---|
| Portable | `make check` | Full output, test count, skips, commit and environment; the C harness is not the kernel verifier |
| Documentation | `python3 tools/check-docs.py` | Language pairs and local links; this does not validate every technical claim |
| Configuration and BPF | Current [workflow](../.github/workflows/check.yml) jobs | Successful validators, compiler/package metadata and object SHA-256 for the same commit |
| Images and installation | Clean preparation using the [guide](../README.md) | Image URL/hash, package manifest and full log; retain the Suricata/backports limitation until retested |
| Isolation | Selected LAB_ID, routes and scoped firewall | Denied-path tests plus a positive control; a configuration file alone is insufficient |
| XDP | Build, verifier, attachment and maps | Native/generic mode, build arguments, program/maps and before/after counters |
| SYN and scan policy | Identical bounded load in selected modes | Generator parameters, counters, trusted sources, window and independent client responses |
| HTTP and IDS/IPS | Normal and selected blocked requests | HTTP 200 positive control; for IPS, correlated EVE SID and blocked delta; HTTP 000 alone does not prove IPS |
| Monitoring | API, heartbeat, timestamps and data | Current [catalogue](../monitoring/catalog.py) objects, fresh values and Problems history; do not reuse old item counts |
| Notifications | Problem/recovery, queue, SMTP and recipient | Delivery record and recipient confirmation; SMTP acceptance differs from inbox delivery |
| Recovery | [Snapshot, disk and DB workflows](backup-restore.en.md) | Validated operations on the owned LAB_ID, preserved data and an application probe after recovery |
| Deployment | [Ansible on the target](deployment.en.md) | Successful application and service verification on that target; syntax-check is insufficient |

## Per-experiment record

Record commit, date/time zone, LAB_ID, host/guest kernel, image hashes, package versions, interface and XDP mode, load parameters, expected outcome and observed outcome. Preserve commands, exit codes, before/after values and a control HTTP request. For restore, identify the recovery point and possible loss of newer data.

Distinguish passed, failed, skipped and not run. Hosted CI is not evidence for KVM, a live dashboard or host recovery. A checksummed BPF artifact is not a cryptographic provenance signature.

Keep local reports in `reports/` outside Git. Before attaching release evidence, remove credentials, raw mail, private inventory and personal information according to the [data policy](data-lifecycle.en.md). A demonstration made from saved output remains a replay rather than a new live experiment.
