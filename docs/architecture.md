# Целевая микросервисная архитектура

Базовая реализация — один модульный control plane с изолированными adapter- и
evidence-границами. Целевые сервисы описаны в ADR; независимый production
runtime ещё не заявлен.

Live three-VM acceptance для текущей ветки не выполнена. Остальные ОС и ISA должны отображаться как `UNKNOWN`, `BLOCKED` или `FEASIBLE`, а не как доказанная
поддержка. QEMU/KVM, XDP, Suricata, nginx, Zabbix/PostgreSQL и Ansible остаются
отдельными проверяемыми модулями с независимым evidence.
