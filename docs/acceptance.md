# Acceptance

Приёмка последовательно подтверждает host admission, lifecycle/QEMU, dual-NIC,
XDP, Suricata, client coverage, monitoring/evidence и cleanup. Каждый шаг требует
durable receipt и независимого evidence.

`make acceptance-check` остаётся read-only и не является live acceptance.
