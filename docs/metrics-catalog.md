# Каталог метрик

Каталог является производным от `monitoring/catalog.py`: **34 исходных элемента,
15 зависимых скоростей**. Ключи ниже должны совпадать с source catalog и
передаваться с корректной единицей/типом; отсутствие telemetry — unknown, а не
нулевое значение.

## Ключи

`xdp.scan_mode` `xdp.scan_events` `xdp.scan_drop` `scan.enabled` `scan.up`
`scan.active` `scan.alerts` `scan.capture_drops` `scan.evictions` `scan.details`
`ids.enabled` `ids.up` `ids.alerts` `ids.blocked` `ids.parse_errors`
`ids.kernel_drops` `xdp.loaded` `xdp.mode` `xdp.syn` `xdp.pass` `xdp.drop`
`xdp.map_full` `xdp.fragment_drop` `xdp.events` `net.rx_packets` `net.rx_bytes`
`http.available` `http.requests` `http.limited` `http.errors5xx`
`http.parse_errors` `http.up` `http.status` `http.latency`

## Производные скорости

`xdp.scan_events.rate` `xdp.scan_drop.rate` `ids.alerts.rate`
`ids.blocked.rate` `ids.kernel_drops.rate` `xdp.syn.rate` `xdp.pass.rate`
`xdp.drop.rate` `xdp.map_full.rate` `xdp.fragment_drop.rate`
`net.rx_packets.rate` `net.rx_bytes.rate` `http.requests.rate`
`http.limited.rate` `http.errors5xx.rate`
