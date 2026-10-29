![OPLA — лаборатория безопасности Linux](assets/demo/banner.svg)

# OPLA Security Lab

**Практическая работа по обнаружению, предупреждению и ликвидации последствий компьютерных атак.**

OPLA — изолированный Linux-стенд для изучения eBPF/XDP, Suricata, nginx и Zabbix.
Три виртуальные машины позволяют создать конечную нагрузку, наблюдать решения
защиты и проверить HTTP с независимого клиента. Результат работы — отчёт с
командами, исходными данными и обоснованными выводами.

[Быстрый старт](#быстрый-старт) · [Методичка](docs/methodology.md) ·
[Документация](docs/README.md) · [Соответствие ТЗ](docs/requirements-traceability.md) ·
[Вопросы и ответы](#частые-вопросы)

[![GitLab pipeline](https://gitlab.com/k3rnel_co0n/opla-security-lab/badges/main/pipeline.svg)](https://gitlab.com/k3rnel_co0n/opla-security-lab/-/pipelines)
[![Лицензии компонентов](https://img.shields.io/badge/license-MIT_%2B_GPL-245de8?style=flat-square)](LICENSING.md)

## Демонстрация

![Архитектура лаборатории и сохранённые результаты опытов](assets/demo/overview.gif)

*Схема показывает текущую архитектуру. Числовые сцены — визуализация сохранённого
вывода оператора от 24.10.2026; темп анимации не отражает время исполнения.*
[Статичный кадр](assets/demo/overview-poster.png) · [Данные и происхождение](assets/demo/README.md) ·
[Текстовый результат](assets/demo/results.txt).

<details>
<summary><strong>Содержание README</strong></summary>

- [Возможности и устройство](#как-устроен-опыт)
- [Требования и запуск](#быстрый-старт)
- [Результаты экспериментов](#что-показывает-опыт)
- [Команды управления](#ежедневные-команды)
- [Уведомления и API token](#почтовые-уведомления)
- [Учебные материалы](#учебный-комплект)
- [Проверки и статус](#проверки-и-статус)
- [Частые вопросы](#частые-вопросы)
- [Источники и участие](#технологии-и-первичные-источники)

</details>

## Как устроен опыт

1. **Создать нагрузку.** Attacker отправляет конечный поток в изолированную data network.
2. **Наблюдать решение.** XDP предоставляет counters, Suricata — EVE alerts, nginx — HTTP-ответы.
3. **Проверить результат.** Client измеряет доступность, Zabbix показывает метрики, отчёт связывает evidence.

![Три роли и отдельные data/management сети](docs/figures/topology.svg)

XDP ограничивает IPv4 TCP SYN и поддерживает scan policy. Suricata обнаруживает
события; блокировка требует отдельно проверенного IPS-режима. nginx ограничивает
HTTP-запросы. Текущий каталог Zabbix содержит **49 items, 23 triggers и 5 страниц**.
[Каталог метрик](docs/metrics-catalog.md) · [Путь пакета](docs/figures/packet-path.svg) ·
[Модель доверия](docs/security-model.md).

## Быстрый старт

Нужны Linux x86_64, systemd, KVM, QEMU/libguestfs, cloud-init tooling, nftables,
Python/PyYAML, Make, OpenSSH, Docker Engine и Compose. Create проверяет минимум
**5 GiB MemAvailable**. Для полного опыта ориентир — 12 GiB RAM и 30 GiB
свободного диска; это запас для планирования, а не измеренный минимум. [Полные требования](docs/test-host-spec.md) и
[подготовка host-зависимостей](docs/deployment.md#1-подготовка-локального-qemu-хоста).

### Установка и запуск

Команды выполняются **на выделенном или явно допущенном тестовом хосте**.
Create меняет host networking; delete безвозвратно удаляет выбранные VM-диски.
Трафик разрешён только в data network своей лаборатории.

Сначала получите исходники и перейдите в каталог проекта:

```bash
git clone https://gitlab.com/k3rnel_co0n/opla-security-lab.git
cd opla-security-lab
```

Затем проверьте исходники и выполните шаги ниже:

**1. Подготовьте образы трёх ролей.**

```bash
make bootstrap
make images
```

Образ victim содержит Suricata, PyYAML, nginx и BPF toolchain; attacker —
hping3, nmap, arp-scan, yersinia и tcpdump. Готовые проверенные образы
переиспользуются. Для прерванной сборки — [восстановление images](docs/user-guide/commands.md).

**2. Установите проверенный snapshot и CLI.**

```bash
python3 bin/opla-system-install.py --source "$PWD"
sudo python3 bin/opla-system-install.py --source "$PWD" --install \
  --destination /opt/opla --expected-sha256 DIGEST
python3 /opt/opla/bin/opla-cli-install.py install
sudo install -d -o root -g root -m 0755 /var/lib/opla
```

Замените `DIGEST` выводом первой команды после review. Установка копирует код
и образы в **новый** root-owned каталог. Для обновления существующей версии
выберите другой путь и используйте его в дальнейших командах.
[Установка и обновление](docs/local-system-install.md). Checkout и `/opt` независимы.

**3. Создайте лабораторию и выберите напечатанный ID.**

```bash
opla lab create --confirm-host-changes
opla lab list
opla lab select lab-XXXXXXXX
opla lab ready
```

`lab-XXXXXXXX` в примерах заменяется реальным ID. Ожидается `cloud-init done`
для всех трёх VM. Если `LAB_DIR` задан в окружении, он имеет приоритет над
сохранённым выбором.

**4. Активируйте защиту и мониторинг.**

```bash
opla lab activate lab-XXXXXXXX
opla xdp stats
opla ids status
```

Активация настраивает гостевые модули, Zabbix/PostgreSQL, dashboard и collector.
Provisioning запросит учётные данные Zabbix. Откройте [локальный Zabbix](http://127.0.0.1:8080),
смените начальный пароль и проверьте свежесть Latest data выбранного host.
[Руководство по Zabbix](docs/zabbix-guide.md).

**5. Выполните конечный сценарий.**

```bash
opla scenario check syn-scan-baseline --lab lab-XXXXXXXX
opla scenario run syn-scan-baseline --lab lab-XXXXXXXX --confirm lab-XXXXXXXX
```

Сохраните report directory из вывода. Для вывода о доступности на всём
интервале нужна [непрерывная проверка с client](docs/task-client-coverage.md).
[Пошаговый учебный опыт](docs/methodology.md).

## Что показывает опыт

![Сохранённые результаты SYN и отдельного HTTP burst](assets/demo/results.png)

Карточка построена из [пользовательского transcript от 24.10.2026](assets/demo/observed-results.json).
В SYN-опыте counters выросли на **2003 SYN**, **300 pass**, **1703 drop**;
отдельный HTTP burst дал **11 ответов 200** и **189 ответов 429**.
Фоновые SYN могут влиять на counters. Эти числа не являются измерением pps,
гарантией предотвращения атаки или доказательством непрерывной доступности.

Suricata evidence и полный dashboard в этой исторической записи не показаны.
Сравнивайте данные только внутри одного опыта: результат SYN и HTTP burst
не объединяется в одну временную серию.
[Текстовая версия результатов](assets/demo/results.txt) ·
[Offline CLI/evidence-worker demo](assets/demo/services/README.md) ·
[Все демонстрации](docs/demonstrations.md).

## Ежедневные команды

| Действие | Команда |
|---|---|
| Выбрать лабораторию | `opla lab list` → `opla lab select lab-XXXXXXXX` |
| Проверить VM / guest readiness | `opla lab status` · `opla lab ready` |
| Проверить защиту | `opla xdp stats` · `opla ids status` |
| Проверить Suricata marker | `opla ids test` |
| Остановить сбор метрик | `opla monitoring stop` |
| Остановить VM, сохранив диски | `opla lab stop` |
| Продолжить работу | `opla lab start` → `opla lab ready` |

### Удалить все лаборатории

Для одного стенда после сохранения результатов:

```bash
opla monitoring stop
opla lab stop
opla lab delete lab-XXXXXXXX --confirm-lab lab-XXXXXXXX
```

Для массового удаления используйте [готовый Bash-блок с подтверждением](docs/data-lifecycle.md#9-удалить-все-зарегистрированные-лаборатории).
Он останавливается при первой ошибке ownership-проверок. Shared Zabbix, история
БД и role images сохраняются. [Backup и восстановление](docs/backup-restore.md).

## Почтовые уведомления

Получатели задаются пользователем — от 1 до 20 адресов. Gmail используется как
SMTP sender через локальный Tor SOCKS5; это факультативная интеграция.
Worker следует за выбранным lab и ведёт отдельные очереди.

### После создания API token в Zabbix

Для новой конфигурации запустите `alert_delivery.py configure`. Если
`~/.config/opla/alerts.json` уже существует, замените token без повторного setup:

```bash
python3 /opt/opla/monitoring/alert_delivery.py api-token
python3 /opt/opla/monitoring/alerts_service.py install
```

Смена списка адресов — действие `recipients`. Token и Gmail app password
вводятся скрыто. [Полная настройка, тест письма и диагностика API](monitoring/README.md#пошаговая-настройка-уведомлений).
Если установленная копия не знает этих действий, сначала
[обновите snapshot](docs/local-system-install.md#обновление-установленного-cli).

## Учебный комплект

| Материал | Содержание |
|---|---|
| [Методические указания](docs/methodology.md) | Теория, две схемы, установка, опыт и восстановление |
| [ФОС](docs/fos.md) | 5 практических заданий, 12 вопросов самопроверки, тест из 15 вопросов |
| [Шаблон отчёта](docs/report-template.md) | Результаты, fingerprints, client coverage и выводы |
| [Соответствие ТЗ](docs/requirements-traceability.md) | Требования исходного PDF и условия итоговой приёмки |
| [Средства и лицензии](docs/software.md) | Версии, назначение, установка и незакрытые лицензионные проверки |

`make docs` собирает студенческий PDF. Ключ преподавателя собирается отдельно
через `make docs-teacher`. Нужны локальные зависимости из
[tools/requirements-docs.txt](tools/requirements-docs.txt). [Каталог документации](docs/README.md).

## Способы развёртывания

**Полный встроенный стенд — локальный QEMU/KVM attacker/victim/client.**
Ansible может [подготовить QEMU-хост](docs/deployment.md#1-подготовка-локального-qemu-хоста)
или настроить [отдельный Debian 13 security node](docs/deployment.md).
Server profile имеет свой scope; это отдельная конфигурация от учебных трёх VM.
Доступ к удалённому узлу описан для SSH, bastion и уже настроенного VPN.
[Выбор платформы и ограничения](docs/platform-compatibility.md).

## Проверки и статус

```bash
python3 -m compileall -q bin tests
make check
make acceptance-offline
python3 tools/check-documentation.py
```

Offline-проверки не заменяют KVM, verifier на реальном ядре и live-доставку в
Zabbix. Чистая полная апробация и лицензионная сверка точных сборок остаются
отдельными условиями приёмки. [Сохранённый offline-отчёт и hashes](docs/evidence/chat-integration-20261030.json) ·
[Runtime readiness](docs/runtime-readiness.md) · [Протокол приёмки](docs/acceptance.md).

## Технологии и первичные источники

| Слой | Документация |
|---|---|
| Виртуализация и ОС | [QEMU](https://www.qemu.org/docs/master/system/index.html) · [KVM](https://docs.kernel.org/virt/kvm/) · [Debian Cloud](https://cloud.debian.org/images/cloud/) |
| Защита ядра | [Linux BPF](https://docs.kernel.org/bpf/) · [XDP](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/) · [libbpf](https://github.com/libbpf/libbpf) |
| IDS и HTTP | [Suricata 7.0](https://docs.suricata.io/en/suricata-7.0.10/) · [nginx limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) |
| Мониторинг | [Zabbix 7.0](https://www.zabbix.com/documentation/7.0/en/manual) · [API](https://www.zabbix.com/documentation/7.0/en/manual/api) · [PostgreSQL](https://www.postgresql.org/docs/16/) |
| Управление | [nftables](https://netfilter.org/projects/nftables/) · [OpenSSH](https://www.openssh.com/manual.html) · [systemd](https://www.freedesktop.org/software/systemd/man/latest/) |
| Сборка и поставка | [Docker Compose](https://docs.docker.com/compose/) · [Ansible](https://docs.ansible.com/) · [GitLab CI](https://docs.gitlab.com/ci/) |

[Полный список средств](docs/software.md) · [Источники теории](docs/sources.md) ·
[Версии и воспроизводимость](docs/versions.md).

## Частые вопросы

**Почему `recipients` или `api-token` не распознаётся?**

Установленный `/opt` snapshot старше checkout. Обновите код по
[инструкции установки](docs/local-system-install.md#обновление-установленного-cli).
Git pull обновляет исходники; пользовательский CLI вызывает свою установленную копию.

**Почему `lab activate` требует trusted installation?**

Привилегированные операции принимают root-owned код и проверяют locks/receipts.
Установите проверенный snapshot. Смена ownership рабочего checkout и отключение
проверок не являются процедурой установки.

**Что делать с оставшимся `.qcow2.part`?**

Проверьте candidate и отсутствие его использования, затем примените
`opla system image-resume --role victim` для нужной роли.
[Подробности восстановления](docs/user-guide/commands.md). Образы работающих VM не перезаписываются.

**Почему график показывает старые числа?**

Проверьте выбранный lab/host и время последнего sample. Нулевая нагрузка и
отсутствие свежих данных — разные состояния. См. [диагностику мониторинга](monitoring/README.md).

**Выполнено ли ТЗ полностью?**

Учебные материалы подготовлены, offline-проверки выполняются. Для итоговой
приёмки нужны чистый live-прогон, точные manifests версий/лицензий и согласование
преподавателя. [Последовательная проверка шести критериев ТЗ](docs/requirements-traceability.md#5-последовательная-проверка-критериев-приёмки).

## Помощь и участие

Начните с [диагностики](docs/operations.md) и [справочника CLI](docs/user-guide/commands.md).
В [GitLab issue](https://gitlab.com/k3rnel_co0n/opla-security-lab/-/issues) приложите
commit, шаги воспроизведения и обезличенный вывод. Секреты и private keys не публикуются.

[CONTRIBUTING](CONTRIBUTING.md) · [SECURITY](SECURITY.md) ·
[Лицензия проекта](LICENSE) · [Лицензии компонентов](LICENSING.md) ·
[История изменений](docs/CHANGELOG.md).
