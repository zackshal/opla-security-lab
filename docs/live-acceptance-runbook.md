# Live acceptance runbook

Выполняйте только на отдельно допущенном Debian x86_64 host. До запуска
сохраните host admission, commit/source hashes и подтверждение scope.

1. Проверьте `make acceptance-check` и установите Ansible environment.
2. Для полного monitoring-профиля зафиксируйте `OPLA_ZABBIX_USER`,
   `OPLA_ZABBIX_PASSWORD` и `OUTPUT_DIR`. Без credentials activation может
   завершиться `BLOCKED`; это не обходится маркировкой `SKIPPED`.
3. Запустите `bash ci/live/run-live-acceptance.sh` один раз.
4. Сохраните manifest, verification, logs и evidence до cleanup.
5. При любом failed/unknown step не повторяйте destructive действие вслепую;
   сохраните receipt и используйте точный lab ID для recovery.

Ожидаемый результат неполного или неавторизованного запуска — `BLOCKED`, а не
PASS. Этот документ не выполняет и не разрешает host mutation.
