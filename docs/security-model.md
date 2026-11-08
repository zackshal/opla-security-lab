# Модель безопасности

Management и data сети разделены двумя NIC/bridge; управление не должно идти
через XDP data path. Операции с VM требуют явного lab ID, ownership checks и
durable receipts. Evidence verifier fail-closed: неполный, неоднозначный или
небезопасный bundle получает `BLOCKED`.

Это учебный стенд, а не production DDoS-защита.
