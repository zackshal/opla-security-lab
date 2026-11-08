# Integration runbook

1. Собрать admission и проверить dedicated-host scope.
2. Проверить ownership/locks, затем создать и настроить QEMU-лабораторию.
3. Проверить client, nginx, Suricata, XDP и monitoring evidence по отдельности.
4. Сопоставить timestamps и identities, затем выполнить cleanup и post-cleanup
   inventory.

При timeout, неизвестном exit status или конфликте ownership **do not retry**:
сохраните receipt и переходите к recovery. QEMU и Suricata требуют независимых
проб; client coverage обязательна для вывода о трафике. Cleanup должен быть
явным, подтверждённым и проверенным по host key/ресурсам. `NOT TESTED` и
`BLOCKED` нельзя выдавать за PASS.
