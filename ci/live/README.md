# `ci/live/` — live-acceptance для ТЗ №2 и №5

Тонкая обёртка вокруг одного портативного оркестратора. GitLab и GitHub
отличаются только entrypoint; сама логика одинаковая.

## Состав

- `run-live-acceptance.sh` — единственная точка входа, платформенно-независимая.
- `verify-evidence.py` — валидатор `manifest.json` и хэшей; выдаёт PASS/BLOCKED.
- `cleanup-stale-labs.sh` — ручная уборка после сбоя.
- `manifest-schema.json` — контракт формата manifest.
- `lib/common.sh` — env, логи, `step`, `capture`, `cleanup_lab`.
- `lib/preflight.sh` — KVM, RAM, disk, tools, `sudo -n`, outbound.
- `lib/lifecycle.sh` — bootstrap → images → install → create → ready →
  activate → scenario → recovery.
- `lib/evidence.sh` — версии, хэши, отчёты, manifest.

## Локальная проверка обвязки
```bash
OPLA_DRY_RUN=1 ci/live/run-live-acceptance.sh
```

В dry-run не выполняются host probes, `sudo`, сеть, QEMU, CLI или lifecycle.
Создаётся синтетический `manifest.json`, а итог намеренно `BLOCKED` (exit 2),
поскольку dry-run не является acceptance evidence. Это проверяет только форму
артефактов и verifier; для реального результата нужен dedicated host.

## Полный прогон (на выделенном хосте)
```bash
sudo -v # закэшировать sudo, иначе прервётся на activate
OPLA_ZABBIX_USER=... OPLA_ZABBIX_PASSWORD=...
bash ci/live/run-live-acceptance.sh
```

В CI это делает job `live_acceptance` (GitLab) или workflow `Live Acceptance`
(GitHub). См. `docs/live-acceptance-runbook.md`.

## Переменные

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `OPLA_SCENARIO` | `syn-scan-baseline` | имя сценария |
| `OPLA_SKIP_RECOVERY` | `0` | пропустить stop/start-drill |
| `OPLA_KEEP_LAB` | `0` | оставить лабораторию после прогона |
| `OPLA_DRY_RUN` | `0` | безопасный синтетический отчёт без host probes; итог BLOCKED |
| `OPLA_ZABBIX_USER` / `OPLA_ZABBIX_PASSWORD` | — | активация Zabbix |
| `OUTPUT_DIR` | `$CI_PROJECT_DIR/live-acceptance-output` | куда складывать артефакты |

## Проверка результата вручную
```bash
python3 ci/live/verify-evidence.py --check live-acceptance-output
ci/live/cleanup-stale-labs.sh lab-XXXXXXXX
```

Recovery всегда получает один точный lab ID; автоматический поиск по префиксу
запрещён, поскольку ID создаются случайно и selection не доказывает ownership.


Печатает `{"overall_status": "PASS"|"BLOCKED", "blockers": [...]}` и
перезаписывает `verification.json`. Это ровно то, что job проверяет
финальным шагом скрипта.

## Чего этот комплект не делает

- Не заменяет `make check` и `make acceptance-offline` — это отдельные jobs.
- Не запускает clang verifier и KVM-приёмку вне своего стенда.
- Не устанавливает сам runner.
- Не настраивает Zabbix. Если активация требует credentials и без них завершается
  ошибкой, acceptance останавливается fail-closed; `SKIPPED` для Zabbix возможен
  только после успешной остальной активации и не означает PASS всей приёмки.
