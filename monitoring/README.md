# Мониторинг

В подсистеме мониторинга я разделил сбор телеметрии, настройку объектов Zabbix и доставку уведомлений. Состояние источника данных и состояние защитного механизма рассматриваются отдельно.

Полный порядок запуска: [README](../README.md#метрики-и-панели-zabbix).

Источники: pinned BPF maps, sysfs, nginx JSON log/probe, Suricata EVE и пассивный scan detector. Host bridge получает данные по SSH и отправляет в Zabbix trapper. Пароль API нужен provisioning, а не collector.

Collector адресует victim по его management IP (`state.py` разрешает data
identity в management identity), использует отдельный per-lab `known_hosts` с
`StrictHostKeyChecking=yes` и ограничивает SSH 10 секундами/128 KiB вывода.
Первичное заполнение `known_hosts` сейчас происходит через `accept-new` в SSH
helper стенда: это TOFU-bootstrap, а не независимая проверка fingerprint. Для
настоящей верификации при первом подключении требуется отдельный источник
ожидаемого host key.

`catalog.py` содержит 34 исходных значения и 15 скоростей: всего 49 items. `setup.py` управляет 23 triggers, 5 graphs и dashboard из 5 страниц. Повторная настройка обновляет управляемые объекты; свою панель клонируйте отдельно. Политика Zabbix из `policy.json` не меняет предотвращение в XDP или nginx.

```bash
make monitoring-stop
python3 monitoring/diagnose.py --lab "$LAB_DIR"
make monitoring-start
```

Диагностика и фоновый collector разделяют блокировку. Смотрите свежесть Latest data и дельты counters; скорости требуют свежих отсчётов. `xdp.loaded=1` — boolean одной подключённой программы. Счётчики capture/sysfs не являются полным учётом native XDP DROP.

Изменения состояния отправляются через ограниченный outbox
`~/.local/state/opla/monitoring/runtime/<LAB_ID>/pending-events.json`. Он переживает рестарт
collector и очищается после полного успешного Zabbix ACK. Provisioning receipt,
журнал и outbox хранятся вне каталога программы, поэтому работают с защищённой
установкой в `/opt/opla`. Секрет Compose хранится в
`~/.config/opla/monitoring.env` с режимом `0600`. Если БД уже существует, но
файл секрета отсутствует, `monitoring up` автоматически переносит доступный
legacy `monitoring/.env`; системная установка также переносит его в config
пользователя и исключает `.env` из root-owned snapshot. Если старого файла нет,
запуск останавливается и просит восстановить пароль из защищённой копии. Новый
пароль для прежнего volume не генерируется, а существующий пользовательский
секрет не перезаписывается.

Доставка имеет
семантику at-least-once: сбой между ACK и очисткой может повторить событие.
Очередь ограничена 1000 событий и 1 MiB; при переполнении старые события не
выбрасываются, collector пишет ошибку и требует устранить backlog. Журнал и
outbox — локальные данные пользователя; сохраняйте их вместе с evidence и не
считайте одиночный лог доказательством живой доставки.

SQL в `sql/` читает БД. Runtime, `.env` и локальные секреты не публикуются. Web/receiver слушают localhost 8080/10051; PostgreSQL port наружу не опубликован. Не удаляйте Docker volume ради исправления графика.

Уведомления Gmail + Proton: `alert_delivery.py` и `alerts_service.py`; конфигурация в `~/.config/opla/alerts.json`, очередь в `~/.local/state/opla-alerts/`. Gmail/Tor — общий SMTP-транспорт двух получателей. `configure-mail.py` — альтернативный provisioning штатного Zabbix media type; не включайте оба пути одновременно без намеренного дублирования.
