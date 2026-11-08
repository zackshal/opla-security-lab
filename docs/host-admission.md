# Host Admission

Admission собирает только read-only сведения: идентификатор машины, ОС/ISA,
`/dev/kvm`, память, диск, интерфейсы и allowlisted tool metadata. Экспорт
подписывается/проверяется отдельно от исполняемых команд и импортируется как
evidence; импорт не запускает VM и не изменяет сеть.

Обязательные поля и provenance должны быть полными, свежими и привязанными к
machine-id. Неполный отчёт остаётся `NOT TESTED`/`UNKNOWN`, а известная
несовместимость — `BLOCKED`. Наличие файла отчёта не является доказательством
capability или готовности.

Перед P14 оператор должен подтвердить dedicated-host scope и сохранить source
hash, timestamp, collector provenance и независимую проверку machine identity.
