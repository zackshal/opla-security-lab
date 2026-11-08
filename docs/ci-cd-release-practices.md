# CI/CD и release practices

CI выполняет syntax, unit, documentation и offline acceptance contracts. Live
acceptance должна запускаться отдельным явно авторизованным job с retention
evidence и без неявного cleanup чужих лабораторий.
