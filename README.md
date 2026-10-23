# Учебный стенд защиты от SYN flood на eBPF и XDP

Три ВМ Debian в отдельной сети: attacker создаёт ограниченный поток SYN,
victim фильтрует его и обслуживает HTTP, client проверяет доступность сервиса.
Zabbix на хосте хранит счётчики и события, показывает графики и состояние защиты.

Начните с [методички](docs/methodology.md). Она содержит подготовку чистой системы,
команды, ожидаемые результаты, содержание отчёта и ограничения эксперимента.

```bash
make bootstrap
make image
make up
make ready
make xdp-all
make monitoring-up
# Открыть http://127.0.0.1:8080 и сменить начальный пароль.
make monitoring-configure
make monitoring-start
make xdp-test
make xdp-dashboard
```

Команды выполняются обычным пользователем; sudo вызывается при создании/удалении ВМ.
Если SSH пока недоступен, подождите загрузки ВМ и повторите `make ready`.
Порог можно изменить: `make xdp-unload`, затем `make xdp-all THRESHOLD=200`.
При нескольких стендах добавляйте `LAB_DIR=/var/lib/opla/lab-...` к каждой команде.

## Документы

- `docs/methodology.md` — полное задание и методические указания.
- `docs/fos.md` — задания, вопросы и тест.
- `docs/teacher-key.md` — ответы и критерии для преподавателя.
- `docs/software.md` — средства, лицензии, версии, системные требования.
- `docs/acceptance.md` — соответствие ТЗ и протокол апробации.
- `docs/report-template.md` — структура отчёта студента.
- `docs/CHANGELOG.md` — что и зачем исправлено.
- `docs/figures/` — схемы в SVG.
- `monitoring/README.md` — Zabbix и диагностика сбора данных.

Проверка без ВМ: `make check`. Фактические версии: `make versions`.
Подготовка пакета не заменяет апробацию на чистом Linux с KVM: её протокол пока не заполнен.

## Остановка

```bash
make monitoring-stop
make down
make monitoring-down
```

Диски работающих ВМ находятся в `/var/lib/opla/lab-...`. При make down они удаляются; после перезагрузки хоста
сначала выполните make down для старого экземпляра, затем make up. предварительно сохраните результаты в `reports/` и `dumps/`.
База Zabbix сохраняется в Docker volume. `monitoring-down` её не удаляет.

## Лицензии

Исходная MIT-лицензия проекта сохранена. XDP-программа имеет GPL-2.0,
поскольку использует GPL-совместимые BPF helpers. Сторонние компоненты
распространяются по собственным лицензиям; см. `docs/software.md`.
