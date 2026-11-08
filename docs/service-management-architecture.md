# Архитектура управления сервисами

Сервисные операции разделены на host lifecycle, guest provisioning, monitoring
и evidence. Каждый слой имеет отдельный receipt и не должен скрывать ошибку
нижнего слоя.
