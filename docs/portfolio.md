# Portfolio summary

OPLA демонстрирует изолированный QEMU/KVM стенд из attacker, victim и client;
XDP/eBPF ограничивает поток, Suricata собирает IDS/IPS evidence, nginx даёт
прикладной HTTP-сигнал, а Zabbix/PostgreSQL и notification paths сохраняют
наблюдаемость.

Сильные стороны проекта: explicit lab identity, ownership-aware lifecycle,
bounded evidence, reproducible offline contracts и fail-closed acceptance
verifier. Live runtime acceptance текущего checkout ещё имеет статус `NOT TESTED`.
