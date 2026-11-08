# ADR: Trust Gate B

Gate B допускает импорт только evidence с проверяемой identity и provenance.
Для подписанных артефактов используются Ed25519 ключи; test keys отделены от
production и не дают production trust. Подпись хранится detached, а revoked
(отозванный) или неизвестный ключ означает `NOT TRUSTED`, даже если JSON
синтаксически корректен. Такой артефакт также остаётся `BLOCKED` для дальнейшей
операции и `NOT TESTED` в части доверенной активации.

Решение об активации production trust — **decision pending**. До отдельного
утверждения проверка остаётся offline/read-only и не активирует live deployment.
