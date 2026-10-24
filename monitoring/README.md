# Мониторинг OPLA

Поддерживаемый путь: pinned BPF maps и HTTP/sysfs victim → SSH JSON → Python bridge на хосте → Zabbix trapper → PostgreSQL → dashboard. ВМ не нужен доступ в Интернет. Zabbix API используется для настройки, пароль API не нужен процессу отправки метрик.

## Автоматический запуск

Из корня проекта после make ready и make xdp-all:

```bash
make monitoring-up
export LAB_DIR="$(python3 bin/state.py --latest)"
bash bin/observability-up.sh
```

Предварительно смените начальный пароль веб-интерфейса. observability-up устанавливает HTTP-политику, deploy сборщика, API-конфигурацию и запускает службу. Dashboard текущего стенда обновляется целиком; свою панель клонируйте под другим именем.

## Каталог

monitoring/catalog.py: 24 входных значения и 13 зависимых скоростей, всего 37 items. monitoring/setup.py: 17 triggers, 5 graphs, dashboard с XDP/events, HTTP, интерфейсом и IDS/IPS. monitoring/policy.json задаёт временные окна и пороги обнаружения. Эти пороги не меняют предотвращение в C или nginx.

Показатель loaded=1 означает одну подключённую программу. Режим хранится строкой native/generic. SYN/pass/drop относятся только к начальным SYN. HTTP-отказы учитываются по limit_req=REJECTED. Локальная HTTP-проверка не заменяет проверку с client. Счётчики sysfs не гарантируют учёт пакетов до native XDP.

## Диагностика

```bash
make monitoring-stop
python3 monitoring/diagnose.py --lab "$LAB_DIR"
make monitoring-start
lab_id="$(python3 bin/state.py "$LAB_DIR" LAB_ID)"
journalctl --user -u "opla-monitor-$lab_id.service" -n 40 --no-pager
tail -n 3 "monitoring/runtime/$lab_id/events.jsonl"
```

Ожидается 24 ACCEPTED. Сборщик использует flock: диагностика и фоновый процесс не работают одновременно. Отсутствующая служба при monitoring-stop допустима. После изменения preprocessing нужны два свежих снимка для скорости; серверу может потребоваться время обновить кеш конфигурации.

В UI сбросьте старые фильтры Latest data, выберите текущий opla-ID. Смотрите свежесть времени, три страницы dashboard и историю Problems. События не означают доставленные внешние уведомления: media type и получатель настраиваются отдельно.

## БД и журналы

```bash
lab_id="$(python3 bin/state.py "$LAB_DIR" LAB_ID)"
docker compose --env-file monitoring/.env -f monitoring/compose.yaml exec -T db psql -U zabbix -d zabbix -v "host_name=opla-$lab_id" < monitoring/sql/security-overview.sql
docker compose --env-file monitoring/.env -f monitoring/compose.yaml logs --tail 40 server web db
```

SQL только читает данные. inspect.sql показывает прежний xdp-каталог, security-overview.sql - все три пространства, aggregate-10s.sql - среднее отсчётов SYN-скоростей.

Полный локальный JSONL: ротация 5 MiB и одна предыдущая часть. Событийная очередь в памяти ограничена 1000 записями, после перезапуска не восстанавливается. Гарантии доставки всех событий нет. Индивидуальные nginx-строки и пакеты в БД не отправляются; счётчики и агрегированные события отправляются примерно раз в 2 секунды. HTTP-курсор находится внутри victim в /var/lib/opla-telemetry; непрочитанный хвост при ротации nginx может потеряться.

## Разделение доступа

8080 и 10051 опубликованы только на localhost. Это необходимое условие нынешней отправки без TLS. Пароль БД в monitoring/.env, SSH-ключи и runtime не входят в Git. Docker-группа эквивалентна широкому административному доступу к хосту; используйте выделенную учебную машину. Не очищайте db-data ради исправления графика.

[Метрики и панели](../README.md#метрики-и-панели-zabbix) · [Suricata](../README.md#suricata)
