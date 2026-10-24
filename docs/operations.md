# Эксплуатация и диагностика

**Русский** · [English](operations.en.md)

Команды выполняются из корня репозитория. Сначала выберите стенд:

```bash
export LAB_DIR="$(python3 bin/state.py --latest)"
printf '%s\n' "$LAB_DIR"
python3 bin/state.py "$LAB_DIR" LAB_ID
python3 bin/state.py "$LAB_DIR" VICTIM_IP
```

`--latest` выбирает по mtime state.env; это не проверка, что ВМ запущены. При нескольких стендах задайте известный `LAB_DIR=/var/lib/opla/lab-...` явно. State не следует загружать через shell source: state.py проверяет владельца, путь и значения.

## Состояние ВМ и управление

```bash
make ready
make ssh VM=victim
```

Внутри victim:

```bash
ip -br address
sudo ss -lntup
sudo systemctl status nginx opla-suricata --no-pager
sudo journalctl -u opla-suricata -n 30 --no-pager
exit
```

`make ready` не повторяет подключение бесконечно. Connection refused сразу после `make vm-resume` может означать, что SSH ещё запускается; проверьте QEMU и повторите ready после готовности, не создавайте новый стенд ради ожидания.

На хосте:

```bash
lab_id="${LAB_DIR##*/}"
sudo systemctl show "qemu-$lab_id-victim.service" -p ActiveState -p SubState -p MainPID
make console VM=victim
```

Консоль доступна только для имеющегося экземпляра; это не отдельная виртуальная машина.

## XDP: загрузка и изменение политики

```bash
make xdp-stats
bash bin/source-map.sh
bash bin/xdp-scan-policy.sh observe
```

Не выполняйте последовательно observe/block/off, если хотите оставить конкретный режим. `make xdp-deploy` копирует код/collector, но не заменяет уже прикреплённую программу. Изменение THRESHOLD в shell не меняет ранее собранный object.

При намеренной смене программы:

```bash
make monitoring-stop
make xdp-unload
make xdp-all THRESHOLD=100 MAX_SOURCES=4096
bash bin/xdp-scan-policy.sh block
make monitoring-start
```

Это прерывает XDP-защиту и пересоздаёт карты. Счётчики до/после reload принадлежат разным эпохам. Trusted sources wrapper читает из состояния выбранного lab. Перед block должен оставаться доступен management path.

## Первичные данные внутри victim

```bash
sudo ip -details link show dev ens3
sudo bpftool net show
sudo bpftool prog show pinned /sys/fs/bpf/opla/program
sudo bpftool map show
sudo bpftool -p map dump pinned /sys/fs/bpf/opla/maps/xdp_stats
sudo bpftool -p map dump pinned /sys/fs/bpf/opla/maps/syn_windows
```

`xdp_stats` per-CPU: значения CPU суммируются. `xdp_scan_drop` входит в `drop`; отдельно прибавлять его как новые потери нельзя. Отброшенный повреждённый заголовок не обязан увеличивать SYN counters. `window_age_seconds` в source map — возраст окна, не время последнего пакета. `map_full` требует внимания: автоматического удаления source states нет.

## Suricata, HTTP и пассивный detector

```bash
make ids-status
make ids
make ips
make ids-off
bash bin/scan-detector.sh status
```

Это справочник отдельных команд, не рецепт выполнить их подряд: последний ids-off отключит движок. Выберите нужный режим. В IPS остановка engine без снятия NFQUEUE может закрыть HTTP-путь; для штатного отключения используйте ids-off, который удаляет собственную очередь.

```bash
bash bin/security-http.sh apply
bash bin/security-http-test.sh
make ids-test
```

`ids-test` сохраняет evidence и HTTP-ответы. HTTP 000 сам по себе означает сетевой timeout, а не доказательство IPS: требуются EVE SID и рост blocked decisions вместе с обычным HTTP 200. Исторические parse_errors сравниваются по дельте; отсутствие capture.kernel_drops в NFQUEUE stats не является ошибкой JSON.

Native XDP может отбрасывать пакеты раньше AF_PACKET. Поэтому пассивный detector не обязан посчитать все пробы, которые блокирует XDP. ARP-scan и часть Nmap ниже порога разрешены; статус closed — ответ TCP RST, filtered — отсутствие/фильтрация ответа по оценке Nmap, а не название конкретного защитного механизма.

## Мониторинг и почта

```bash
make monitoring-stop
python3 monitoring/diagnose.py --lab "$LAB_DIR"
make monitoring-start
lab_id="${LAB_DIR##*/}"
journalctl --user -u "opla-monitor-$lab_id.service" -n 40 --no-pager
python3 monitoring/alert_delivery.py status
journalctl --user -u opla-alerts.service -n 30 --no-pager
```

Collector и diagnose используют одну блокировку. Наличие значения в Latest data не доказывает свежесть: смотрите last check и collector heartbeat. SMTP accepted — сервер принял сообщение, но доставку во входящие подтверждает получатель. Счётчики очереди и poll state не следует путать с количеством сетевых атак.

## Docker и сеть CI

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
docker network inspect opla-ci-bridge
sudo /usr/sbin/nft list chain inet filter opla_ci_forward
sudo systemctl show opla-ci-firewall.service -p Result -p ExecMainStatus
sudo systemctl list-timers opla-ci-firewall.timer --no-pager
```

CI egress exception относится к отдельной сети CI, не к lab bridge. Разрешение в таблице Docker не отменяет drop в другой base chain. Не очищайте nft ruleset ради диагностики. Служба OPLA CI не восстанавливает удалённые таблицы Docker целиком.

GitHub Actions работает на hosted runner и не требует вашего Tor/CI-proxy. Локальный GitLab Runner и Tor toolkit хранятся отдельно от публичных исходников.
