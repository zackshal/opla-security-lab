# Безопасность

**Русский** · [English](SECURITY.en.md)

OPLA — release candidate с отдельными лабораторным и серверным профилями. Модель угроз, границы fail-closed и незавершённые проверки описаны в корневом README.

Не публикуйте приватные ключи, SMTP passwords, monitoring/.env, runtime logs, packet captures и backups БД. XDP и NFQUEUE меняют обработку пакетов; сначала проверяйте их на изолированном data interface с отдельным управлением.

Уязвимости сообщайте непублично через доступный контакт владельца или private vulnerability reporting платформы. Production SLA и независимая сертификация не заявлены.
