# GitLab CI and delivery

Pushes and merge requests run portable checks and configuration validation. A branch with an open merge request uses the merge request pipeline to avoid duplicate push pipelines.

| Job | Result |
| --- | --- |
| portable | Python/C behavior checks; log retained for 14 days |
| configuration | Suricata IDS/IPS configuration and local rules validation; Ansible syntax check |
| bpf-build | BPF object built on Debian 12 with THRESHOLD=100 and MAX_SOURCES=4096; tool versions and checksum retained for 30 days |
| delivery | Small BPF archive with commit SHA, build settings, checksums and validation boundary |
| deploy-staging | Optional manual Ansible deployment from the protected default branch |

The configuration jobs need a Linux container runner and internet access to Debian repositories. No privileged container, Docker-in-Docker, KVM access or BPF attachment is required. The pipeline uses distribution tags and current package candidates, so it records versions but does not promise bit-for-bit reproducible builds.

Compilation and CPU tests do not replace kernel verifier acceptance, multi-CPU behavior, live packet enforcement, Zabbix API acceptance or performance measurements. Consult test logs for skipped checks. Live lab evidence remains outside CI.

## Staging deployment

The deploy job is absent unless OPLA_DEPLOY_ENABLED=1. It also requires a protected default branch. The job is manual, serialized by resource_group and requires a runner tagged opla-deploy. Configure that runner as protected and give it access only to the designated staging server. Enabling deployment makes the manual job a pipeline gate.

Create protected GitLab CI/CD variables of type File:

- OPLA_DEPLOY_INVENTORY: real inventory containing the opla group and a dedicated Debian 13 target.
- OPLA_DEPLOY_VARS: reviewed variables corresponding to ansible/vars.example.yml, including the database and Zabbix passwords. Store it outside Git. The example file contains deliberately invalid credentials and documentation addresses.
- OPLA_SSH_PRIVATE_KEY: a separate deployment key with access to that server.
- OPLA_SSH_KNOWN_HOSTS: host keys verified with the server administrator through a trusted channel.

Set OPLA_DEPLOY_ENABLED to 1 only after reviewing the target and configuring the protected files. The target needs Docker Compose before the playbook runs. The SSH account needs the become access required by the playbook; do not disable host-key verification to work around connection failures.

The BPF object comes from this pipeline and its SHA-256 is checked before deployment. No secret files are published as artifacts. SSH material is copied to a private temporary directory and removed on exit. A checksum detects accidental modification; it is not a signature or independent provenance proof.

This is the existing dedicated-server playbook, not the QEMU lab workflow. It does not automatically enable or persist the new XDP scan block policy, deploy the passive scan service, configure the Gmail/Tor poller, or create VM snapshots. Those integrations need a separate server acceptance run. Do not label an unexecuted deployment as production-ready.

After first deployment, independently verify the attached program, counters, HTTP health, Suricata mode, fresh Zabbix values, source-map capacity and rollback procedure. Repository CI/CD configuration is not proof that these checks have passed.

## Repository history

The initial import preserves existing Git history. Previously committed PDF/DOCX files remain in history even when ignored later. This setup does not scan historical content for secrets or remove historical documents. Keep the initial project private until publication contents have been reviewed.
