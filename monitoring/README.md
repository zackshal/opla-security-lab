# Мониторинг

Полный порядок запуска: [README](../README.md#метрики-и-панели-zabbix).

Источники: pinned BPF maps, sysfs, nginx JSON log/probe, Suricata EVE и пассивный scan detector. Host bridge получает данные по SSH и отправляет в Zabbix trapper. Пароль API нужен provisioning, а не collector.

`catalog.py` содержит 34 исходных значения и 15 скоростей: всего 49 items. `setup.py` управляет 23 triggers, 5 graphs и dashboard из 5 страниц. Повторная настройка обновляет управляемые объекты; свою панель клонируйте отдельно. Политика Zabbix из `policy.json` не меняет предотвращение в XDP или nginx.

```bash
make monitoring-stop
python3 monitoring/diagnose.py --lab "$LAB_DIR"
make monitoring-start
```

Диагностика и фоновый collector разделяют блокировку. Смотрите свежесть Latest data и дельты counters; скорости требуют свежих отсчётов. `xdp.loaded=1` — boolean одной подключённой программы. Счётчики capture/sysfs не являются полным учётом native XDP DROP.

SQL в `sql/` читает БД. Runtime, `.env` и локальные секреты не публикуются. Web/receiver слушают localhost 8080/10051; PostgreSQL port наружу не опубликован. Не удаляйте Docker volume ради исправления графика.

Уведомления Gmail + Proton: `alert_delivery.py` и `alerts_service.py`; конфигурация в `~/.config/opla/alerts.json`, очередь в `~/.local/state/opla-alerts/`. Gmail/Tor — общий SMTP-транспорт двух получателей. `configure-mail.py` — альтернативный provisioning штатного Zabbix media type; не включайте оба пути одновременно без намеренного дублирования.
