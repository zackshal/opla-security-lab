# Security

Я разрабатываю OPLA для изолированных учебных испытаний. Приведённые меры безопасности относятся к лабораторному стенду; использовать его на действующей сети без отдельной оценки рисков нельзя.

OPLA is a release candidate with separate lab and dedicated-server profiles. Threat boundaries, fail-closed scope and outstanding acceptance checks are documented in the root README.

Do not publish private keys, SMTP credentials, monitoring/.env, runtime logs, packet captures or database backups. Native XDP and NFQUEUE change packet handling; test on an isolated data interface with a separate management path before deployment.

Report vulnerabilities privately through the repository owner's security contact or the hosting platform's private vulnerability reporting. No production SLA or independent security certification is claimed.
