# Deployment

Подготовка host и guest images выполняется Ansible/скриптами с явными
dependency manifests. QEMU/KVM, Suricata, nginx, Zabbix/PostgreSQL, XDP и
Ansible являются отдельными проверяемыми границами; необязательные модули не
должны скрывать отказ базового lifecycle.

Перед публикацией образа проверяются role package manifest и pinned base-image
SHA-512. На host admission проверяются `qemu-system-x86_64`, `dnsmasq`, `nft`,
`ip`, `python3` и другие allowlisted tools. Отсутствие зависимости —
`BLOCKED`, без частичного live deployment.
