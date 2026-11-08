# Виртуальные машины

Лаборатория состоит из attacker, victim и client под QEMU/KVM. Management NIC
используется для SSH и evidence, data NIC — для ограниченного эксперимента.
Создание, запуск и удаление выполняются только lifecycle CLI с явным lab ID.

Без live acceptance состояние VM считается `NOT TESTED`.
