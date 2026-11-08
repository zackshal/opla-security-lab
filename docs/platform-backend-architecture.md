# Platform backend architecture

Platform backend разделяет read-only fact collection, admission decision и
runtime operation. Факты не являются готовностью: отсутствующий KVM/tool/memory
даёт `BLOCKED`, неизвестный факт — `NOT TESTED`/`UNKNOWN`, а `FEASIBLE` требует
явного scope и provenance.

Текущий backend ориентирован на Debian x86_64 и QEMU/KVM. Другие платформы
остаются экспериментальными до отдельной проверки.
