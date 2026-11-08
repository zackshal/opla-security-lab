# Спецификация тестового хоста

Документ описывает входные условия, а не доказательство готовности конкретного
хоста. Перед P14 должен быть собран и независимо проверен read-only admission
evidence. Отсутствующие или противоречивые данные имеют статус `BLOCKED` или
`NOT TESTED`.

## Минимум

- Debian x86_64 с доступным символьным устройством `/dev/kvm` и правом текущего
  пользователя открыть его.
- `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, `dnsmasq`, `ip`, `nft`,
  `flock`, `python3` и `systemd-run`.
- Два физических/логических интерфейса: management `ens3` и изолированный lab
  data-интерфейс `ens4` (фактические имена проверяются admission-отчётом).
- `MemAvailable` не менее 5120 MiB `MemAvailable`; at least 5120 MiB `MemAvailable`.
  План запуска выделяет attacker 1024 MiB,
  victim 2048 MiB, client 512 MiB и оставляет 1536 MiB резерва для QEMU и
  хоста.

Роли используют `qemu-system-x86_64`: attacker и client подключаются к data и
management сетям, victim — к ним же с отдельным контролем nftables. DHCP/DNS
для лаборатории обслуживается `dnsmasq`; это не разрешение менять сеть хоста
вне явно созданных ресурсов лаборатории.

## Статусы

`FEASIBLE` означает только соответствие наблюдаемым admission-фактам.
`NOT TESTED` означает отсутствие live acceptance, а `BLOCKED` — недостаток или
противоречие обязательного evidence. Этот документ сам по себе не доказывает
работу QEMU, KVM, XDP, Suricata или Zabbix.
