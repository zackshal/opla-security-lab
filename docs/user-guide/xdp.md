# XDP и политика сканирования

XDP наблюдает новые IPv4 TCP SYN и имеет режимы `off`, `observe`, `block`.
Переход в block требует подтверждённых доверенных источников и evidence
attachment/program/map identity. `syn_windows` использует bounded LRU map, чтобы
полный state не оставлял новые источники навсегда заблокированными.

Сборка, verifier, attachment, counters, policy update и ownership-aware unload
должны быть проверены отдельно. Исходники и offline tests не доказывают kernel
verifier или live packet effectiveness: до этого статус `NOT TESTED`.
