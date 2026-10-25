# Каталог метрик и источников

**Русский** · [English](metrics-catalog.en.md)

Каталог я документирую непосредственно по исходному коду, чтобы число показателей в методичке не расходилось с реализацией. Перечень ниже характеризует текущую конфигурацию, а не автоматически подтверждает успешное создание каждого объекта в работающем Zabbix.

Сгенерировано по `monitoring/catalog.py` (источник истины): **34 исходных элемента, 15 зависимых скоростей, всего 49 элементов**.
Настройка `monitoring/setup.py` дополнительно определяет **23 триггера, 5 графиков и 5 страниц dashboard**. Эти числа характеризуют код, а не фактическое состояние API на конкретном стенде.

## Исходные элементы

| Ключ Zabbix | Тип | Единица | Назначение |
|---|---|---|---|
| `xdp.scan_mode` | Numeric unsigned | — | XDP scan policy: off=0 observe=1 block=2 |
| `xdp.scan_events` | Numeric unsigned | — | XDP distinct-port threshold crossings |
| `xdp.scan_drop` | Numeric unsigned | — | New SYN packets blocked by XDP scan policy |
| `scan.enabled` | Numeric unsigned | — | Port-scan detector configured (0/1) |
| `scan.up` | Numeric unsigned | — | Port-scan detector heartbeat (0/1) |
| `scan.active` | Numeric unsigned | — | Sources exceeding distinct-port threshold |
| `scan.alerts` | Numeric unsigned | — | Port-scan threshold crossings |
| `scan.capture_drops` | Numeric unsigned | — | Passive detector socket drops |
| `scan.evictions` | Numeric unsigned | — | Passive detector state evictions |
| `scan.details` | Text | — | Last port-scan source and target |
| `ids.enabled` | Numeric unsigned | — | Suricata configured (0/1) |
| `ids.up` | Numeric unsigned | — | Suricata running (0/1) |
| `ids.alerts` | Numeric unsigned | — | Suricata alerts |
| `ids.blocked` | Numeric unsigned | — | Suricata blocked alert decisions |
| `ids.parse_errors` | Numeric unsigned | — | EVE parse errors |
| `ids.kernel_drops` | Numeric unsigned | — | Capture kernel drops (engine epoch) |
| `xdp.loaded` | Numeric unsigned | — | XDP attached (0/1) |
| `xdp.mode` | Character | — | XDP attachment mode |
| `xdp.syn` | Numeric unsigned | — | SYN observed |
| `xdp.pass` | Numeric unsigned | — | SYN allowed |
| `xdp.drop` | Numeric unsigned | — | SYN blocked |
| `xdp.map_full` | Numeric unsigned | — | SYN map capacity drops |
| `xdp.fragment_drop` | Numeric unsigned | — | IPv4 TCP fragment drops |
| `xdp.events` | Log | — | Security interval events |
| `net.rx_packets` | Numeric unsigned | — | ens3 RX packets (driver) |
| `net.rx_bytes` | Numeric unsigned | B | ens3 RX bytes (driver) |
| `http.available` | Numeric unsigned | — | HTTP JSON log readable (0/1) |
| `http.requests` | Numeric unsigned | — | HTTP requests observed in JSON log |
| `http.limited` | Numeric unsigned | — | HTTP requests rejected by rate limiter |
| `http.errors5xx` | Numeric unsigned | — | HTTP server errors (5xx) |
| `http.parse_errors` | Numeric unsigned | — | Invalid HTTP telemetry records |
| `http.up` | Numeric unsigned | — | Local HTTP probe returns 200 (0/1) |
| `http.status` | Numeric unsigned | — | Local HTTP probe response code |
| `http.latency` | Numeric unsigned | us | Local HTTP probe duration |

## Зависимые скорости

| Ключ Zabbix | Master item | Единица |
|---|---|---|
| `xdp.scan_events.rate` | `xdp.scan_events` | pps |
| `xdp.scan_drop.rate` | `xdp.scan_drop` | pps |
| `ids.alerts.rate` | `ids.alerts` | pps |
| `ids.blocked.rate` | `ids.blocked` | pps |
| `ids.kernel_drops.rate` | `ids.kernel_drops` | pps |
| `xdp.syn.rate` | `xdp.syn` | pps |
| `xdp.pass.rate` | `xdp.pass` | pps |
| `xdp.drop.rate` | `xdp.drop` | pps |
| `xdp.map_full.rate` | `xdp.map_full` | pps |
| `xdp.fragment_drop.rate` | `xdp.fragment_drop` | pps |
| `net.rx_packets.rate` | `net.rx_packets` | pps |
| `net.rx_bytes.rate` | `net.rx_bytes` | Bps |
| `http.requests.rate` | `http.requests` | rps |
| `http.limited.rate` | `http.limited` | rps |
| `http.errors5xx.rate` | `http.errors5xx` | rps |

## Интерпретация

Зависимые скорости вычисляются Zabbix из последовательных накопительных значений (Change per second), поэтому после сброса счётчика или потери данных требуется новая корректная пара измерений. `xdp.loaded=1` подтверждает подключение XDP к интерфейсу, но не доступность HTTP или исправность всех датчиков. `http.up` проверяется локально на victim, а независимый client проверяется отдельно. `scan.*` относится к пассивному детектору портов; `ids.*` — к Suricata.

Отсутствие свежего значения — неизвестное состояние телеметрии, а не нулевая нагрузка. `net.rx_*` отражают счётчики интерфейса, а не гарантированно все пакеты, отброшенные native XDP. `ids.kernel_drops` относится к эпохе запуска сенсора и не должен интерпретироваться как общий сетевой loss.

При добавлении показателя изменяют каталог, источник данных, передачу, документацию и тесты согласованно.
