# Остановка, хранение и удаление данных

## Сначала выбрать необходимый уровень

| Действие | Результат |
|---|---|
| Остановить collector / alerts | ВМ и БД сохраняются |
| Штатно выключить три ВМ | Диски/snapshots сохраняются; возможен vm-resume при сохранённой сети |
| `make monitoring-down` | Контейнеры мониторинга остановлены/удалены, DB volume сохраняется |
| `make down` | Выбранный lab, включая рабочие диски и внутренние snapshots, удаляется |
| Compose `down --volumes` | Удаляется также PostgreSQL volume этого Compose project |
| Удалить images/backup | Можно потерять backing files или единственный способ восстановления |

Далее команды относятся только к OPLA. Обычное удаление файлов не является гарантированным стиранием на SSD/snapshots/backup-системах. Отзыв токенов и удаление их локальных копий — разные операции.

## Где лежат данные

| Путь/объект | Содержимое |
|---|---|
| `/var/lib/opla/lab-*` | Working disks, seed ISO, state.env, QMP sockets, внутренние snapshots |
| `images/` | Base и role qcow2; working disks могут ссылаться на них |
| `monitoring/.env` | Пароль PostgreSQL и image tags |
| `monitoring/runtime/` | Provisioning metadata, collector events/state |
| `reports/`, `dumps/` | Результаты опытов, возможные captures |
| `opla-monitoring_db-data` | PostgreSQL Docker volume (фактическое имя проверьте inspect) |
| `~/.config/opla/alerts.json` | Gmail app password, адреса и Zabbix API token |
| `~/.local/state/opla-alerts/` | Очередь уведомлений и poll cursor |
| `~/.config/opla/gitlab-runner/` | GitLab Runner auth token и конфигурация |
| `~/.config/opla/tor-bridges/` | Public bridge feed/config, timer helper; не почтовые секреты |
| `~/opla-backups`, `~/opla-archive`, `~/opla-transfer` | Пользовательские backups, quarantine, переданные source archives |

## 1. Остановить наблюдение

```bash
make monitoring-stop
systemctl --user stop opla-alerts.service
```

Это не удаляет queue, secrets и DB. Для постоянного отключения почтовой службы:

```bash
python3 monitoring/alerts_service.py remove
```

Команда удаляет unit, но оставляет private config/queue. Если unit уже отсутствует, повторный remove может завершиться ошибкой — сначала проверьте его состояние.

## 2. Сохранить ВМ или удалить выбранный lab

Для сохранения: штатное shutdown в каждой ВМ, проверка MainPID=0 и offline backup из [руководства](backup-restore.md). Не используйте make down для остановки с сохранением.

Для окончательного удаления именно выбранного экземпляра после backup:

```bash
export LAB_DIR="$(python3 bin/state.py --latest)"
printf 'Будет удалён lab: %s\n' "$LAB_DIR"
python3 bin/state.py "$LAB_DIR" LAB_ID
make down LAB_DIR="$LAB_DIR"
```

cleanup останавливает его QEMU/DHCP, удаляет связанные TAP/bridge и отдельную nftables table, затем удаляет весь LAB_DIR. Другие экземпляры выбирайте и удаляйте по одному. Нельзя удалять весь /var/lib или nft ruleset. Не полагайтесь на `--latest`, если работаете с несколькими lab.

## 3. Остановить мониторинг, сохранив БД

```bash
make monitoring-down
```

Скрипт останавливает host collectors и выполняет Compose down без volumes. DB volume и monitoring/.env остаются для следующего старта.

## 4. Удалить БД мониторинга

Это отдельная операция потери данных. Сначала dump + отдельный restore drill, остановка collector/alerts и проверка фактического volume:

```bash
docker inspect opla-monitoring-db-1 --format '{{json .Mounts}}'
```

Если контейнер уже остановлен/удалён, используйте docker volume ls/inspect и сверяйте label com.docker.compose.project=opla-monitoring. Затем из нужного checkout:

```bash
docker compose --env-file monitoring/.env -f monitoring/compose.yaml down --volumes
```

Удаляются volumes данного Compose project, включая DB. Не используйте docker system prune --volumes для очистки OPLA: на хосте есть другие проекты. Имя Compose project задано в monitoring/compose.yaml; проверьте, что не работаете с другим сервисом на том же имени.

## 5. Очистить локальные отчёты, старые архивы и образы

Сначала посмотрите состав и размер:

```bash
du -sh reports dumps images "$HOME/opla-backups" "$HOME/opla-archive" "$HOME/opla-transfer"
git status --short
```

Выбирайте существующие каталоги; отсутствие одного пути не является повреждением проекта. Список игнорируемых файлов можно только посмотреть:

```bash
git clean -ndX
```

Это dry run, а не разрешение запускать git clean -fdX/-fdx. Игнорируемые файлы включают секреты, backup и активные образы. Удаляйте конкретные подтверждённые файлы/каталоги через `rm -i` или `rm -rI`, сохраняя images/.gitkeep и dumps/.gitkeep.

Base/role qcow2 нельзя удалять, пока на них ссылаются сохранённые working disks, даже если ВМ выключены. Сначала инвентаризация всех lab и qemu-img info --backing-chain на остановленных дисках. `make down` одного lab не доказывает, что image не используется другим экземпляром.

Backups/quarantine можно убрать после подтверждённого restore и сохранения независимой копии. Не удаляйте все поколения одновременно. Архивы в Downloads, ~/vim и ~/opla-transfer удаляются отдельно от репозиториев; rm -i принимает конкретные filenames.

## 6. Удалить локальную почтовую конфигурацию

Только после остановки opla-alerts.service:

```bash
rm -i -- "$HOME/.config/opla/alerts.json"
rm -rI -- "$HOME/.local/state/opla-alerts"
```

Удаление queue сбрасывает дедупликацию/курсоры: после повторной настройки уже активные проблемы могут отправиться снова. Для окончательного отказа от интеграции отзовите Gmail app password и Zabbix API token в их системах. Из резервных копий и чужих почтовых ящиков эти команды ничего не удаляют.

## 7. Локальная инфраструктура GitLab Runner / Tor

Она находится в отдельном ~/vim/opla-local-runner, не в публичном checkout. Сначала запретите новые jobs и дождитесь завершения активной:

```bash
cd ~/vim/opla-local-runner
python3 runner.py pause
```

Остановить только её Compose project, сохранив Tor state:

```bash
python3 - <<'PY'
import json
import runner
reference = json.loads((runner.STATE/'image.json').read_text())['reference']
runner.compose(['down'], reference)
PY
```

Для удаления Tor state этой композиции вместо down используется down --volumes — только если намеренно удаляете её данные. Не останавливайте host Tor, если он нужен почте или другим приложениям. Удаление регистрации Runner в GitLab и отзыв access token выполняются отдельно от остановки Docker.

Отключить bridge refresh timer после остановки proxy:

```bash
systemctl --user disable --now opla-tor-bridges.timer
```

Отключить автоматическое CI firewall exception и сделать его цепочку пустой:

```bash
sudo systemctl disable --now opla-ci-firewall.timer
sudo systemctl disable opla-ci-firewall.service
sudo /usr/sbin/nft flush chain inet filter opla_ci_forward
```

Это выключает CI egress через данное исключение. Не удаляйте chain, пока на неё есть jump. Файлы service/timer, /etc/opla/ci-firewall.json, /usr/local/sbin/opla-ci-firewall и sysctl.d удаляются адресно после проверки, какие другие задачи используют IPv4 forwarding; не переключайте глобальный ip_forward в 0 автоматически.

## 8. Серверный профиль

Перед удалением server data сохраните dump и конфигурацию. Штатно выключить engine с удалением его NFQUEUE:

```bash
sudo python3 /opt/opla/security/suricata/manage.py off
sudo systemctl disable --now opla-telemetry.service opla-xdp.service
```

opla-xdp ExecStop отказывается снимать чужую программу. Pins server profile находятся в /sys/fs/bpf/opla-server. nginx и vendor Suricata являются системными пакетами: не удаляйте их и не восстанавливайте неизвестную прежнюю конфигурацию автоматически.

Удаление /opt/opla, /var/lib/opla-telemetry, /var/log/opla* и /etc/opla-suricata — только после остановки соответствующих служб и определения нужных backup. Единого безопасного «удалить всё на любом сервере» playbook сейчас нет. Локальная очистка не удаляет GitHub/GitLab repositories.
