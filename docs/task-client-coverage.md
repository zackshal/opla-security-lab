# Client coverage

Эксперимент считается покрытым только при наличии непрерывных client probes,
границ интервала, source/destination identity, timestamps и связанного evidence
от XDP/scan/Suricata. Один успешный point probe не заменяет interval coverage.

Отсутствующий, неполный или неоднозначный client artifact — `BLOCKED` для
вывода об эффективности; он не превращается в нулевые ошибки или PASS.
