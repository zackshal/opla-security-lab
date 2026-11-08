# Версии и воспроизводимость

Снимок версий собирается `bin/versions.sh`. Для acceptance сохраняются commit,
hash образов, версии host/guest и Docker RepoDigests. Mutable image source
принимается только через проверенный SHA-512 pin в `bootstrap.sh`.

Исторические значения без привязки к текущему commit имеют статус `NOT TESTED`.
