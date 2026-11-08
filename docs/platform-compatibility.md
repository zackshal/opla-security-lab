# Platform compatibility

Основной target — Debian x86_64 на Linux с KVM. В текущем checkout нет
подтверждения live acceptance для macOS, Windows или других host platforms.
macOS и Windows могут использоваться только как control-plane environments при
отдельной проверке; guest runtime capability не следует из этого факта.

Для неподтверждённых комбинаций ОС/ISA результат — `NOT TESTED`, `UNKNOWN` или
`BLOCKED`; `FEASIBLE` означает только статическую/host-admission совместимость.
В частности, no non-Debian live acceptance evidence exists.
