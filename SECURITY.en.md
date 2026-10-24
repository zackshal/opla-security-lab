# Security

[Русский](SECURITY.md) · **English**

OPLA is a release candidate with separate lab and dedicated-server profiles. The root README documents threat boundaries, fail-closed scope and outstanding acceptance checks.

Do not publish private keys, SMTP credentials, `monitoring/.env`, runtime logs, packet captures or database backups. Native XDP and NFQUEUE change packet handling; test on an isolated data interface with a separate management path.

Report vulnerabilities privately through an available security contact of the repository owner or the hosting platform's private vulnerability reporting. No production SLA or independent security certification is claimed.
