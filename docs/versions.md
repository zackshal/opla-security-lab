# Версии и воспроизводимость

**Русский** · [English](versions.en.md)

Бейджи root README отражают наблюдавшийся запуск 24.10.2026, а не рекомендуемые новейшие пакеты.

| Компонент | Наблюдавшаяся версия | Где |
|---|---|---|
| Debian | 13 | Host / CI portable configuration |
| Debian | 12 | QEMU guests / CI BPF build |
| Linux | 6.1.190 / 6.1.0-54-cloud-amd64 | Victim |
| clang | 14.0.6 | Сборка BPF на victim |
| Python | 3.13.5 host; 3.11.2 guest | Оркестрация / collector |
| QEMU | 10.0.13 | Host |
| nftables | 1.1.3 | Host |
| nginx | 1.22.1 | Victim |
| PostgreSQL | 16.10-alpine | Monitoring container |
| Zabbix | alpine-7.0.19 | Server / Web |
| Suricata | 7.0.10 | Victim, согласованный backports набор |
| GitLab Runner | 19.5.1 | Локальная инфраструктура CI |
| Ansible core | 2.19.3 | Syntax-check трёх playbooks при подготовке текущей редакции |
| Bash | Не записана в предоставленном протоколе | Не подменяется версией из другой среды |

Собрать актуальные данные:

```bash
make versions
bash --version | head -n 1
ansible-playbook --version
```

make versions сохраняет отчёты в reports/; дополнительные команды печатают сведения в терминал. Ansible controller version может отличаться от пакета внутри CI. Для контейнеров фиксируйте также image digest:

```bash
docker inspect --format '{{.Name}} {{.Image}}' opla-monitoring-db-1 opla-monitoring-server-1 opla-monitoring-web-1
docker image inspect postgres:16.10-alpine --format '{{json .RepoDigests}}'
```

Сохранённый tag не гарантирует неизменность образа. Хеш локального downloaded qcow2 подтверждает его конкретное содержимое; скачивание bookworm/latest в другой день может дать другой образ. Для повторения опыта нужны source commit, BPF build arguments, kernel/interface mode, hashes образов, конфигурация правил и before/after evidence.

Security updates выполняются осознанно: новый пакет/ядро требует повторного build/verifier/attach/live теста. Сохранение старого номера на бейдже не является причиной откладывать обновление безопасности.
