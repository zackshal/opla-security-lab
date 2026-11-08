# E2E test plan

План включает preflight/admission, create/configure/ready, service probes,
bounded scenario, client interval coverage, XDP/Suricata/EVE correlation,
Zabbix/PostgreSQL delivery и ownership-aware cleanup. На каждой границе
сохраняются command, exit status, timestamps, identities и source hashes.

До явного разрешения оператора E2E остаётся `NOT TESTED`. Любой missing,
ambiguous или failed evidence переводит соответствующий критерий в `BLOCKED`;
retry не должен повторять неизвестное destructive действие.
