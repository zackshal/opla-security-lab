# Мониторинг

В подсистеме мониторинга я разделил сбор телеметрии, настройку объектов Zabbix и доставку уведомлений. Состояние источника данных и состояние защитного механизма рассматриваются отдельно.

Полный порядок запуска: [README](../README.md#установка-и-запуск).

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

Почтовые уведомления: `alert_delivery.py` и `alerts_service.py`. Однократная
настройка `alert_delivery.py configure` принимает Gmail sender, Zabbix API token,
Gmail app password и список от 1 до 20 адресов-получателей через запятую.
Получатели могут быть на любом почтовом сервисе; Gmail используется как SMTP
отправитель, доставка идёт через локальный Tor SOCKS5. Секреты хранятся в
`~/.config/opla/alerts.json` с режимом `0600`.
Изменить список позже можно командой `alert_delivery.py recipients`; она
сохраняет остальные secrets и требует перезапустить пользовательскую службу
через `alerts_service.py install`, чтобы применить новый список. Заменить
Zabbix API token можно командой `alert_delivery.py api-token`: она проверит
доступ к выбранному lab host, problems и events до сохранения; затем службу
нужно перезапустить через `alerts_service.py install`.

Сборщик следует за пользовательским выбором `opla lab select lab-...` и
автоматически адресует host `opla-<LAB_ID>` в локальном Zabbix. При смене
выбранного стенда он переключает цель без перезапуска и использует отдельную
очередь/cursor в `~/.local/state/opla-alerts/labs/<LAB_ID>/`. Очереди прежних
стендов сохраняются; события не переносятся между lab. `configure-mail.py` —
альтернативный provisioning штатного Zabbix media type; не включайте оба пути
одновременно без намеренного дублирования.


## Пошаговая настройка уведомлений


Почта — отдельная опциональная интеграция поверх событий Zabbix. При первом
подключении пользователь сам задаёт от одного до двадцати адресов-получателей.
Один сохранённый Gmail app password используется только как SMTP-учётная запись
отправителя; получать письма можно на адреса любых почтовых провайдеров.
Конфигурация находится в `~/.config/opla/alerts.json`, очереди и cursors
разделены по стендам в `~/.local/state/opla-alerts/labs/<LAB_ID>/`, служба
systemd пользователя называется `opla-alerts.service`.

Проверить сохранённое состояние без вывода секретов:

```bash
systemctl --user is-active opla-alerts.service
python3 /opt/opla/monitoring/alert_delivery.py status
stat -c '%a %n' "$HOME/.config/opla/alerts.json"
```

Интеграция отправляет почту через локальный Tor SOCKS5 `127.0.0.1:9050`.
Сборщик автоматически читает выбранный `opla lab select lab-...` и обращается к
Zabbix host `opla-<полный-ID-стенда>`. При переключении выбора он переключает
Zabbix-цель и очередь этого стенда; перезапускать службу не требуется. События
и курсоры сохраняются отдельно для каждого стенда и продолжат обработку, когда
он будет выбран снова. Уже начатая SMTP-отправка может завершиться после
переключения выбора. Существующая legacy-очередь будет переиспользована только
если её старый host точно совпадает с выбранным стендом. Удаление стенда не удаляет почтовую конфигурацию,
очереди и не отключает службу. Для работы нужны Zabbix API token, Gmail app
password и запущенный локальный Tor SOCKS endpoint; секреты хранятся в
пользовательском файле с режимом `0600`.

Первичная настройка на установленной копии (только если `alerts.json` ещё нет):

```bash
python3 /opt/opla/monitoring/alert_delivery.py configure
python3 /opt/opla/monitoring/alert_delivery.py test
python3 /opt/opla/monitoring/alerts_service.py install
```

Сначала выберите существующий стенд командой `opla lab select lab-...`.
`configure` запросит Gmail sender, список адресов через запятую, Zabbix API
token и Gmail app password. Проверит, что локальный Zabbix содержит host
выбранного стенда. Дальше служба сама следует за выбором lab. Команда `test`
отправляет настоящее тестовое письмо получателям. Если `alerts.json` уже есть,
`configure` откажется перезаписывать его: сохраните файл и очередь, если хотите
переходить на новую установку, и не копируйте секреты в репозиторий. Старые
конфигурации с фиксированным `host` продолжают работать, когда lab не выбран;
при наличии выбора выбранная лаборатория имеет приоритет. Старый общий queue
файл сохраняется; если его сохранённый host совпадает с выбранным lab, OPLA
продолжит использовать эту очередь, иначе оставит её без изменений и создаст
отдельную очередь выбранного стенда.

### После создания API token в Zabbix

В Zabbix 7.0 API token создаётся в разделе **User settings → API tokens**;
в зависимости от роли управление также доступно через **Users → API tokens**.
Значение token показывается только при создании — сразу сохраните его в
менеджер секретов. Token наследует права назначенного пользователя: для OPLA
нужны доступ к host выбранной лаборатории и чтение событий/problems через API.
Смотрите [официальную документацию Zabbix по User settings и API tokens](https://www.zabbix.com/documentation/7.0/en/manual/web_interface/user_profile)
и [справочник Zabbix API](https://www.zabbix.com/documentation/7.0/en/manual/api).

Затем:

1. Выберите lab, чей host уже создан в Zabbix:

   ```bash
   opla lab select lab-XXXXXXXX
   ```

2. Если `~/.config/opla/alerts.json` **ещё не существует**, запустите первичную
   настройку. Вставьте token только в скрытый интерактивный prompt:

   ```bash
   python3 /opt/opla/monitoring/alert_delivery.py configure
   ```

   Введите Gmail sender, адреса получателей через запятую, API token и Gmail
   app password. Не вставляйте token в командную строку, issue или Git.

3. Если `alerts.json` **уже существует**, не запускайте `configure`: он намеренно
   не перезаписывает секреты. Для изменения только получателей используйте
   `recipients`, затем переустановите/перезапустите службу:

   ```bash
   python3 /opt/opla/monitoring/alert_delivery.py recipients
   python3 /opt/opla/monitoring/alerts_service.py install
   ```

   Эта команда сохраняет текущие API/SMTP secrets.

   Если нужно заменить сохранённый API token, сначала выберите правильный lab,
   затем запустите отдельное действие. Оно проверит token на API версии 7.0,
   доступ к выбранному host, problems и events и только затем сохранит его:

   ```bash
   python3 /opt/opla/monitoring/alert_delivery.py api-token
   python3 /opt/opla/monitoring/alerts_service.py install
   ```

   Token запрашивается скрыто; не вставляйте его в shell history.

4. Для настоящего тестового письма worker не должен уже держать очередь:

   ```bash
   systemctl --user stop opla-alerts.service
   python3 /opt/opla/monitoring/alert_delivery.py test
   python3 /opt/opla/monitoring/alerts_service.py install
   ```

   Успех `test` показывает принятие SMTP-сервером, но не подтверждает появление
   письма во входящих. После установки проверьте выбранную цель через
   `python3 /opt/opla/monitoring/alert_delivery.py status` и журнал через
   `journalctl --user -u opla-alerts.service -n 50 --no-pager`.

Если CLI в `/opt/opla` сообщает, что `recipients` — недопустимое действие,
там стоит старая копия проекта. Git checkout сам не обновляет root-owned
установку; используйте [процедуру обновления в новый snapshot](../docs/local-system-install.md#обновление-установленного-cli).

Команда ручной проверки `alert_delivery.py test` отправляет реальное тестовое
письмо заданным получателям; запускайте её только когда это ожидаемо. Статус SMTP
`accepted` означает, что SMTP сервер принял сообщение, а не подтверждение его
появления во входящих.

Чтобы позже заменить список адресов, выполните интерактивную команду. Она
атомарно обновит только список, сохранив API token и SMTP secret:

```bash
python3 /opt/opla/monitoring/alert_delivery.py recipients
python3 /opt/opla/monitoring/alerts_service.py install
```

Введите полный новый список через запятую. Повторный `install` перезапустит
работающую пользовательскую службу, чтобы она загрузила обновлённые адреса.

В проекте есть также альтернативный путь через штатный Zabbix email media type
(`monitoring/configure-mail.py`). Не включайте оба пути одновременно, если не
нужны дублирующие письма. Удаление lab не отзывает Gmail app password или
Zabbix API token; отзывайте их отдельно, если интеграция больше не нужна.
