# Ansible

Подробный runbook: [локально, SSH, VPN и bastion](../docs/deployment.md).

| Playbook | Назначение | Целевой узел |
|---|---|---|
| `lab-host.yml` | Пакеты для QEMU/KVM-лаборатории; опциональная установка Docker | Выделенный Debian 12/13 amd64 |
| `preflight.yml` | Read-only проверка интерфейса, Docker Compose и controller BPF object | Debian 13 security node |
| `site.yml` | XDP, Suricata, nginx, Zabbix/PostgreSQL и локальная телеметрия | Выделенный Debian 13 security node |

`lab-host.yml` не создаёт ВМ/образы и не запускает мониторинг; для этого остаётся Makefile. `site.yml` не является playbook создания QEMU-стенда. Он требует Docker Compose и собранный объект заранее. Серверная ветка не автоматизирует пассивный AF_PACKET scan detector, Tor и Gmail/Proton polling daemon из лабораторного профиля; optional mail в site.yml — другой путь через Zabbix media type.

Inventory examples не содержат ключей или рабочих адресов. Local connection выполняет задачи на текущем узле без SSH. VPN inventory использует SSH по VPN-адресу: сначала должен существовать маршрут VPN. Создание VPN-туннеля этим комплектом не выполняется.
