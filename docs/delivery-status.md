# Публикация и границы CI/CD

**Русский** · [English](delivery-status.en.md)

На 25.10.2026 GitHub PR 1 объединил актуальные RU/EN карты компонентов и матрицу приёмки. В configuration job добавлен Git до checkout; иначе actions/checkout скачивал архив без .git. Все шесть PR-проверок portable/configuration/bpf-build для push/PR прошли. Merge `66b00e2` получен публичной рабочей копией через fast-forward; дерево чистое. Отдельный post-merge CI этим документом не подтверждается.

Публичный источник: https://github.com/zackshal/opla-security-lab. Состояние старой GitLab.com-копии OPLA не было синхронизировано этим GitHub PR; исторический GitLab pipeline в README не следует считать проверкой любой новой main.

Локальный infra-delivery-lab — другой проект. Его успешные Compose/K3s jobs проверяют llama.cpp и не являются приёмкой production deployment OPLA. Не смешивайте metrics, kernels, VM topology и результаты разных стендов.

В opla-ebpf-reviewed сохранены 25 изменений старых документов/сборщиков. Они не импортируются целиком в публичную main. Историю и атрибуцию повторно не переписываем; обычная публикация выполняется через ветку и PR.

Демонстрация assets/demo/terminal-replay.* остаётся историческим воспроизведением вывода. Для актуального UI требуется [запись действующего интерфейса](../assets/demo/README.md). Новая запись ещё не предоставлена. Критерии испытаний: [acceptance](acceptance.md); текущие версии: [versions](versions.md).
