# ADR: целевые сервисные границы

Сейчас OPLA — модульный монолит с целевыми сервисными границами; независимый production runtime ещё не заявлен. Границы:

- `opla-control` — единственный владелец состояния операции;
- `opla-host-backend` — host admission и QEMU/lifecycle adapter;
- `opla-guest-agent` — guest configure/health/scenario;
- `opla-evidence` — telemetry/report и immutable evidence;
- `opla-monitoring` — publish в monitoring backend.

Каждый запрос содержит exact `operation_id`, `lab_id`, timestamp и envelope.
`UnixServiceRouter` выбирает allowlisted Unix socket, а `JsonLineServiceWorker`
валидирует envelope до handler. Сервисная декомпозиция не отменяет текущие
ownership и cleanup guards.
