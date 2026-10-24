# Versions and reproducibility

[Русский](versions.md) · **English**

README badges describe the observed 2026-10-24 environment, not the latest recommended security releases.

| Component | Observed version | Location |
|---|---|---|
| Debian | 13 | Host / portable configuration CI |
| Debian | 12 | Guests / BPF build CI |
| Linux | 6.1.190 / 6.1.0-54-cloud-amd64 | Victim |
| clang | 14.0.6 | Victim BPF build |
| Python | 3.13.5 host; 3.11.2 guest | Orchestration / collector |
| QEMU | 10.0.13 | Host |
| nftables | 1.1.3 | Host |
| nginx | 1.22.1 | Victim |
| PostgreSQL | 16.10-alpine | Monitoring |
| Zabbix | alpine-7.0.19 | Server / web |
| Suricata | 7.0.10 | Matched backports packages on victim |
| GitLab Runner | 19.5.1 | Separate local CI infrastructure |
| Ansible core | 2.19.3 | Syntax checks of three playbooks |
| Bash | Not recorded | Not inferred from another environment |

```bash
make versions
bash --version | head -n 1
ansible-playbook --version
docker inspect --format '{{.Name}} {{.Image}}' opla-monitoring-db-1 opla-monitoring-server-1 opla-monitoring-web-1
docker image inspect postgres:16.10-alpine --format '{{json .RepoDigests}}'
```

`make versions` writes reports; the remaining commands print diagnostics. Controller and CI versions can differ. Tags do not imply immutable images. Record source commit, build arguments, kernel/interface mode, image hashes, policy configuration and before/after evidence. Downloading a `latest` cloud image another day can produce different bytes.

Security updates require renewed build/verifier/attachment/live checks. An old badge is not a reason to delay security updates.
