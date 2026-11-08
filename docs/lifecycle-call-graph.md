# Граф lifecycle

Поток P14: admission → create → configure → ready → start → probes → durable
receipt. Каждая стадия имеет журнал, owner/resource evidence и bounded timeout;
resume повторяет только незавершённые безопасные проверки и не переигрывает
успешные действия.

При ошибке создание не выбирает «последнюю» лабораторию. Cleanup сначала
останавливает точно подтверждённую лабораторию, затем удаляет только её
owned-ресурсы; ошибка stop запрещает delete. Неопределённое состояние требует
ручного reconciliation и остаётся `BLOCKED`.
