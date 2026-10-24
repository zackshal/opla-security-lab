"""Единые имена, типы и единицы управляемых метрик Zabbix."""
# Имя в SSH JSON, ключ Zabbix, название, тип Zabbix, единица.
DEFINITIONS = [
    ('loaded', 'xdp.loaded', 'XDP attached (0/1)', 3, ''),
    ('mode', 'xdp.mode', 'XDP attachment mode', 1, ''),
    ('syn', 'xdp.syn', 'SYN observed', 3, ''),
    ('pass', 'xdp.pass', 'SYN allowed', 3, ''),
    ('drop', 'xdp.drop', 'SYN blocked', 3, ''),
    ('map_full', 'xdp.map_full', 'SYN map capacity drops', 3, ''),
    ('fragment_drop', 'xdp.fragment_drop', 'IPv4 TCP fragment drops', 3, ''),
    ('events', 'xdp.events', 'Security interval events', 2, ''),
    ('rx_packets', 'net.rx_packets', 'ens3 RX packets (driver)', 3, ''),
    ('rx_bytes', 'net.rx_bytes', 'ens3 RX bytes (driver)', 3, 'B'),
    ('http_available', 'http.available', 'HTTP JSON log readable (0/1)', 3, ''),
    ('http_requests', 'http.requests', 'HTTP requests observed in JSON log', 3, ''),
    ('http_limited', 'http.limited', 'HTTP requests rejected by rate limiter', 3, ''),
    ('http_5xx', 'http.errors5xx', 'HTTP server errors (5xx)', 3, ''),
    ('http_parse_errors', 'http.parse_errors', 'Invalid HTTP telemetry records', 3, ''),
    ('http_up', 'http.up', 'Local HTTP probe returns 200 (0/1)', 3, ''),
    ('http_status', 'http.status', 'Local HTTP probe response code', 3, ''),
    ('http_latency_us', 'http.latency', 'Local HTTP probe duration', 3, 'us'),
]
BY_NAME = {row[0]: row for row in DEFINITIONS}
METRICS = [row[0] for row in DEFINITIONS if row[3] == 3]
RATES = ['syn', 'pass', 'drop', 'map_full', 'fragment_drop', 'rx_packets', 'rx_bytes',
         'http_requests', 'http_limited', 'http_5xx']


def item_key(name):
    return BY_NAME[name][1]
