# Программные средства и версии

**Русский** · [English](software.en.md)

## 1 Окружение, использованное при апробации

В таблице я зафиксировал значения из вывода `make versions` от 24.10.2026. Это версии, наблюдавшиеся в моей среде, а не список рекомендуемых «последних версий».

| Компонент | Фактическое значение |
|---|---|
| Ядро хоста | 7.2.9+deb13-amd64; сборка 7.2.9-1~bpo13+1 |
| QEMU хоста | 10.0.13; пакет 1:10.0.13+ds-0+deb13u1 |
| nftables хоста | 1.1.3 |
| Python хоста | 3.13.5 |
| cloud-image-utils хоста | 0.33-1 |
| dnsmasq хоста | 2.91-1+deb13u2 |
| libguestfs-tools, dpkg | 1:1.54.1-2+deb13u1; бинарную virt-customize повторно зафиксировать |
| Ядро victim | 6.1.0-54-cloud-amd64; 6.1.190-1 |
| Clang | 14.0.6 |
| bpftool | 7.1.0; libbpf 1.1 в выводе version |
| libbpf-dev | 1:1.1.2-0+deb12u1 |
| nginx | 1.22.1-9+deb12u10 |
| hping3 | 3.a2.ds2-10 |
| curl | 7.88.1-10+deb12u15 |
| tcpdump | 4.99.3-1 |
| Zabbix | server/web image alpine-7.0.19 |
| PostgreSQL | image 16.10-alpine; server_version отдельно не показан |

Docker Engine/Compose versions и RepoDigests ещё нужно приложить. Хост содержит пакеты deb13, но /etc/os-release в протокол не включён. install-host.sh автоматизирует только Debian 12; для другой ОС нужна отдельная проверенная инструкция. На более раннем шаге бинарник virt-customize сообщил 1.52.3: для согласования повторите command -v virt-customize, virt-customize --version и dpkg-query -W libguestfs-tools.

SHA256 исходного образа из вывода пользователя: b1b018dc1046fb21815f6cfe4b67ac1d56bc841e19c4ba2c16073031386ad774. Это хеш базового образа, не доказательство неизменности подготовленного образа с nginx.

## 2 Справочник свободных средств

| Средство и целевая версия | Роль и место | Лицензия | Источник |
|---|---|---|---|
| Debian 12 amd64, Linux 6.1 из Debian | Хост и три ВМ | Набор свободных лицензий; ядро GPL-2.0-only | https://www.debian.org/; https://kernel.org/ |
| QEMU 7.2 из Debian 12, KVM ядра | Виртуализация на хосте | QEMU GPL-2.0; отдельные файлы могут иметь иные лицензии; KVM GPL-2.0 | https://www.qemu.org/; https://www.qemu.org/docs/master/about/license.html |
| cloud-init 22.4 из Debian 12 | Начальная настройка ВМ | Apache-2.0 OR GPL-3.0 | https://github.com/canonical/cloud-init |
| cloud-image-utils из Debian 12 | cloud-localds, seed ISO | GPL-3.0 | https://launchpad.net/cloud-utils |
| libguestfs и virt-resize 1.48 из Debian 12 | Подготовка образа на хосте | Библиотека LGPL-2.1+, инструменты GPL-2.0+ | https://libguestfs.org/ |
| Clang/LLVM 14 из Debian 12 | Компиляция BPF внутри victim | Apache-2.0 WITH LLVM-exception | https://llvm.org/ |
| GCC 12 и GNU Make 4.3 из Debian 12 | Пакетные проверки и сборка | GPL-3.0+; GCC Runtime Library Exception где применимо | https://gcc.gnu.org/; https://www.gnu.org/software/make/ |
| libbpf 1.1 из Debian 12 | BPF headers и загрузка через bpftool | LGPL-2.1-only OR BSD-2-Clause | https://github.com/libbpf/libbpf |
| bpftool из Debian 12 | Загрузка и чтение карт | GPL-2.0-only OR BSD-2-Clause для bpftool; зависимости отдельно | https://github.com/libbpf/bpftool |
| iproute2 6.1 из Debian 12 | Интерфейсы, маршруты и привязка XDP | GPL-2.0 | https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/ |
| nftables 1.0 из Debian 12 | Изоляция на хосте | GPL-2.0 | https://netfilter.org/projects/nftables/ |
| dnsmasq из Debian 12 | DHCP-служба на мосту | GPL-2.0 OR GPL-3.0 | https://thekelleys.org.uk/dnsmasq/doc.html |
| OpenSSH 9.2 из Debian 12 | SSH и scp | BSD и другие свободные лицензии файлов | https://www.openssh.com/; https://www.openssh.com/portable.html |
| Nginx 1.22 из Debian 12 | HTTP-сервис victim | BSD-2-Clause | https://nginx.org/ |
| hping3 3.a2.ds2 из Debian 12 | Ограниченный SYN-поток attacker | GPL-2.0 | https://github.com/antirez/hping |
| Python 3.11 из Debian 12 | Сборщик, API, тесты и TUI | PSF-2.0 и совместимые лицензии включённых компонентов | https://www.python.org/ |
| curl 7.88 из Debian 12 | HTTP-проверки и скачивание | curl license, свободная MIT/X11-подобная | https://curl.se/docs/copyright.html |
| tcpdump 4.99 из Debian 12 | Сохранение PCAP | BSD-3-Clause | https://www.tcpdump.org/ |
| socat 1.7 из Debian 12 | Serial-консоль | GPL-2.0 | http://www.dest-unreach.org/socat/ |
| systemd 252 из Debian 12 | Управление службами и ВМ | LGPL-2.1+ для основных компонентов; отдельные компоненты GPL-2.0+ | https://systemd.io/ |
| util-linux 2.38 из Debian 12 | flock и mountpoint | Набор свободных лицензий; конкретный utility по copyright пакета | https://github.com/util-linux/util-linux |
| Git 2.39 из Debian 12 | Версионирование | GPL-2.0 | https://git-scm.com/ |
| Docker Engine CE и Compose v2, версии фиксируются после установки | Контейнеры мониторинга на хосте | Apache-2.0 для Engine/Moby и Compose | https://github.com/moby/moby; https://github.com/docker/compose |
| Zabbix server и web 7.0.19 | Метрики, события, dashboard | AGPL-3.0 | https://www.zabbix.com/license |
| PostgreSQL 16.10 | База Zabbix | PostgreSQL License | https://www.postgresql.org/about/licence/ |

Версии Debian-пакетов в таблице обозначают целевые upstream-линейки, а не точные Debian revision и не подтверждённую апробацию. Репозитории обновляются. Установленные версии нужно сохранить командой make versions; при сдаче заменить целевые значения фактическими либо приложить manifest. Образы контейнеров имеют фиксированные теги; для побайтовой фиксации дополнительно сохраните RepoDigests через docker image inspect. Текущая конфигурация не заявляет, что это последние релизы.

## 3 Требования и установка по месту использования

| Место | Минимум для планирования | Средства | Установка |
|---|---|---|---|
| Хост Debian 12 amd64 | 4 ядра, 12 ГБ RAM, 30 ГБ диска, KVM | QEMU, libguestfs, cloud-localds, nft, dnsmasq, Python, SSH, Docker/Compose | sudo ./bin/install-host.sh |
| victim Debian 12 | 2 vCPU, 2 ГБ RAM, логический диск 10 ГБ | Clang, libbpf-dev, bpftool, Nginx, iproute2, Python | make image; cloud-init/victim.yaml |
| attacker Debian 12 | 1 vCPU, 1 ГБ RAM, логический диск 10 ГБ | hping3, SSH, tcpdump | make image; cloud-init/attacker.yaml |
| client Debian 12 | 1 vCPU, 512 МБ RAM, логический диск 10 ГБ | curl, SSH | make image; cloud-init/client.yaml |
| Контейнеры на хосте | Резерв 3 ГБ RAM и от 5 ГБ диска | Zabbix, PostgreSQL | make monitoring-up |

Ресурсы являются расчётными, а не измеренными минимумами; проверить их достаточность нужно при апробации. Все ВМ используют один подготовленный образ и отдельные overlays. Полный набор пакетов установлен во всех трёх ВМ ради простоты воспроизведения, но роли различаются конфигурацией.

В подготовленном Debian по каждому установленному пакету доступен /usr/share/doc/ИМЯ/copyright. Это первичный источник точных условий конкретной сборки. Сводная таблица не заменяет лицензии зависимостей и файлов. Проприетарных компонентов в предложенном пути нет; Docker Desktop и закрытые плагины не используются.

## 4 Фиксация после апробации

```bash
make versions
docker image inspect zabbix/zabbix-server-pgsql:alpine-7.0.19 \
  --format '{{json .RepoDigests}}'
docker image inspect zabbix/zabbix-web-nginx-pgsql:alpine-7.0.19 \
  --format '{{json .RepoDigests}}'
docker image inspect postgres:16.10-alpine --format '{{json .RepoDigests}}'
```

Сохраните вывод в reports/, приложите downloaded.sha256 и prepared.sha256. Сохраняйте сам подготовленный образ отдельно от Git, иначе тот же recipe позднее может установить более новые обновления пакетов.

Установка Docker основана на официальной инструкции: https://docs.docker.com/engine/install/debian/ (дата обращения: 23.10.2026).
