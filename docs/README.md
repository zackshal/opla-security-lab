# Документация OPLA

Начать с [README](../README.md). Для завершения работы используйте
[чек-лист сдачи](completion-checklist.md): что уже готово и какие проверки ещё нужны.

## Учебный комплект по ТЗ

- [Руководство преподавателя](teacher-guide.md): демонстрация, вопросы и проверка результатов.

- [Методические указания](methodology.md): теория, две схемы, подготовка и девять разделов работы.
- [ФОС](fos.md): практические задания, вопросы и тест; ключ передаётся преподавателю отдельно.
- [Шаблон отчёта](report-template.md), [средства/лицензии](software.md), [версии](versions.md).
- [Соответствие ТЗ и критерии приёмки](requirements-traceability.md).
- Студенческий PDF: `make docs`; отдельный ключ: `make docs-teacher`.

## Пользователю

1. [Установка и обновление](local-system-install.md): checkout, root-owned code и wrapper.
2. [Руководство оператора](operator-guide.md): create/start/ready/stop, права и статусы.
3. [Справочник команд](user-guide/commands.md) и [VM](user-guide/virtual-machines.md).
4. [Демонстрации](demonstrations.md): реальные recordings и их ограничения.
5. [Диагностика](operations.md), [backup/restore](backup-restore.md), [данные и удаление](data-lifecycle.md).

## Архитектура и подтверждение

- Текущий статус и результаты проверок смотрите через `make check`; исторические audit-файлы не входят в public clone.


- [Краткая архитектура](architecture.md), [сервисное управление](service-management-architecture.md), [ADR](adr-microservice-architecture.md).
- [Ресурсы и обычный пользователь](resource-and-user-operation.md), [модель доверия](security-model.md).
- [Платформы](platform-compatibility.md), [multiarch](multiarch-support.md), [host specification](test-host-spec.md).
- [Evidence index](evidence/README.md), [матрица приёмки](acceptance.md), [протокол](run-protocol.md).
- [Runtime readiness](runtime-readiness.md): фактический граф P14–P21, статический отчёт и protocol для FD/process evidence.
- [Host Admission](host-admission.md): как собрать физические read-only evidence вне sandbox и воспроизводимо импортировать оценку без запуска системных команд.
- [ADR по каталогам хранения](adr-opla-storage-layout.md): целевое разделение состояния, VM-дисков и артефактов без автоматической миграции существующих лабораторий.
- [Метрики](metrics-catalog.md), [XDP](user-guide/xdp.md), [Zabbix](zabbix-guide.md).

## Разработка и поставка

- [Engineering workflow](engineering-workflow.md), [offline lifecycle](offline-lifecycle.md).
- [Ansible deployment](deployment.md), [релиз](release.md), [CI/CD](ci-cd-release-practices.md).
- [CHANGELOG](CHANGELOG.md).

## Как читать документы

Операционные руководства описывают текущий код. Файлы `task-*.md`, датированные
протоколы и старые CHANGELOG entries сохраняют историю конкретных изменений;
их числа тестов и промежуточные ограничения не являются статусом текущего HEAD.
Учебные материалы methodology/fos/portfolio не заменяют руководство установки.

При расхождении документа и кода результат не считается PASS: воспроизведите
проверку, сохраните команду, exit status, scope и source hashes. Новый GIF/SVG
или health сервиса не доказывает работу VM, XDP/IDS или production deployment.

Проверить local links и literal CLI examples без исполнения операций:

```bash
python3 tools/check-documentation.py
```
