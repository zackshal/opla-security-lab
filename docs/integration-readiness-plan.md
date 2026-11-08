# Integration readiness plan

P14–P21 проверяются последовательно: host admission, lifecycle/QEMU, dual-NIC,
XDP, Suricata, scenario/client coverage, monitoring/evidence и cleanup.
Каждый критерий требует durable receipt и независимого evidence.

Текущий checkout не содержит live three-VM acceptance. До её выполнения статус
остаётся `NOT TESTED`; недостаток обязательного evidence или failed cleanup —
`BLOCKED`. Offline tests не являются заменой dedicated-host проверки.
