# opla-ebpf — лабораторный стенд по eBPF/XDP

Дисциплина: «Обнаружение, предупреждение и ликвидация последствий компьютерных атак».

**Тема:** обнаружение и предотвращение SYN-флуд атак с использованием eBPF/XDP.

## Быстрый старт

```bash
git clone <url> opla-ebpf && cd opla-ebpf
make bootstrap        # скачать базовые образы (~600 МБ)
sudo make up          # создать br-labN + 3 ВМ (attacker, victim, client)
make console VM=victim
sudo make down        # остановить и удалить стенд
```
