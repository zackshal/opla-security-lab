# Zabbix

Zabbix/PostgreSQL — optional monitoring module полного профиля. По умолчанию
activation его включает; для профиля без monitoring используйте
`OPLA_ENABLE_MONITORING=0 make lab-activate LAB=lab-XXXXXXXX CONFIRM=lab-XXXXXXXX`.
После activation с включённым monitoring
проверьте host, Latest data, items/triggers и сохраните evidence. Отсутствие API
или dashboard runtime подтверждается как `NOT TESTED`, а не как PASS.

Глобальная остановка требует явного подтверждения и затрагивает все лаборатории:
`make monitoring-down CONFIRM_GLOBAL=I_UNDERSTAND_GLOBAL_MONITORING_DOWN`.
