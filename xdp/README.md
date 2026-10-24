# XDP: ограничение начальных IPv4 TCP SYN

Основное правило: SYN=1, ACK=0; для каждого source IP первые THRESHOLD пакетов фиксированного окна получают PASS, остальные DROP. По умолчанию 100 пакетов за 1 секунду. Политика действует на все TCP-порты, включая SSH; NAT объединяет клиентов под одним лимитом.

```bash
make xdp-unload
make xdp-all THRESHOLD=100
make xdp-stats
make xdp-dashboard
```

Загрузчик не заменяет уже подключённую программу автоматически. clang -target bpf и verifier проверяются на victim. Native пробуется первым; generic используется только при ошибке привязки драйвера, не для обхода отказа verifier. BTF не означает, что программа использует CO-RE.

## Алгоритм и карты

Разбираются Ethernet, до двух VLAN-тегов, IPv4 IHL и длины TCP. IPv4/TCP-фрагменты запрещены до подсчёта SYN. Длина IPv4 сравнивается с доступным количеством байтов без сложения packet pointer с total: это исправило наблюдавшийся отказ verifier.

syn_windows: hash-map, по умолчанию 4096 source IP (MAX_SOURCES), значение spin lock/count/start_ns. Блокировка защищает совместное состояние окна; первый пакет нового окна считается как 1. Старые адреса автоматически не удаляются. Если добавить новый адрес не удалось, SYN отбрасывается и растёт map_full.

xdp_stats: per-CPU array u64:

| Индекс | Имя | Смысл |
|---|---|---|
| 0 | syn | Учтённые начальные SYN |
| 1 | pass | Пропущенные учтённые SYN |
| 2 | drop | Отброшенные учтённые SYN |
| 3 | map_full | Отказы нового source IP при заполнении карты |
| 4 | fragment_drop | Отброшенные фрагменты IPv4/TCP |

Программа закреплена в /sys/fs/bpf/opla/program, карты в /sys/fs/bpf/opla/maps. collect.py проверяет ID программы на ens3, декодирует u64 и суммирует CPU. Командный JSON теперь также содержит метрики sysfs и HTTP; они не являются дополнительными BPF-картами. trace_pipe не используется.

## Проверка ядра

```bash
make ssh VM=victim
sudo bpftool net show
sudo bpftool prog show pinned /sys/fs/bpf/opla/program
sudo bpftool -p map dump pinned /sys/fs/bpf/opla/maps/xdp_stats
exit
bash bin/traffic-scenario.sh syn
```

Нагрузка конечна. Сохраняйте before/after, команду сборки, результаты независимого client и время. Процент hping packet loss не равен доле XDP_DROP. Временные ID программ и карт не фиксируйте в скриптах.

## Ограничения

UDP, ACK без SYN и IPv6 этим rate limiter не ограничиваются. Повреждённые заголовки могут отбрасываться без роста SYN-drop. Сумма pass+drop относится к учтённым SYN, а не ко всему трафику. Фиксированные окна допускают всплеск у границы. Распределённые источники и заполнение map ограничивают применимость. Измерения ускорения относительно netfilter и предельного pps не проведены.

[Архитектура](../README.md#архитектура) · [Испытания](../README.md#проверки-и-эксперименты)
