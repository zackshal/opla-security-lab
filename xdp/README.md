# eBPF/XDP

В этом модуле я реализовал обработку входящих пакетов средствами eBPF/XDP и ограничение начальных TCP SYN. Описание фиксирует точные условия применения политики, чтобы не распространять выводы на неохваченные протоколы.

Полное описание и команды: [README](../README.md#защита-ebpfxdp).

`xdp_ddos_protect.c` проверяет Ethernet/VLAN/IPv4/TCP, ограничивает начальные SYN по источнику и поддерживает distinct-port scan policy. Default: SYN 100 за 1 секунду, map 4096 sources. Scan threshold: 8 различных портов за фиксированное окно 60 секунд; block TTL 30 секунд.

`scan-policy.py` задаёт off/observe/block и два trusted IPv4 source. Trusted sources обходят scan policy, но не SYN rate limit. При пересоздании карт режим сбрасывается в off. Политика относится к новым SYN, а не ко всем пакетам источника. Обновление сверяет program ID/tag, список `map_ids`, ID/type каждой pinned map и ABI policy map с root-owned load receipt перед изменением map.

Карты: `syn_windows` (state + spin lock), `xdp_policy` (режим + trust), `xdp_stats` (per-CPU u64). Индексы stats: 0 syn, 1 pass, 2 drop, 3 map_full, 4 fragment_drop, 5 xdp_scan_events, 6 xdp_scan_drop. Scan drop входит в общий SYN drop. Повреждённые пакеты могут отбрасываться без увеличения этих SYN-счётчиков.

```bash
make xdp-stats
bash bin/source-map.sh
bash bin/xdp-scan-policy.sh observe
```

Перед загрузкой `fingerprint.py validate-build` сверяет SHA-256 как исходника, так и BPF-объекта с manifest. Несовпадение блокирует загрузку. Scan policy сверяет ровно одну запись ABI от `bpftool`, включая типы полей; пустой, неоднозначный или malformed ответ не вызывает update.

Loader допускает продолжение только при явном `attached=off` на `ens3`; отсутствующее или неизвестное состояние блокирует операцию. При ошибке attach pins сохраняются для сверки, wildcard-очистки нет. Unloader требует совпадения интерфейсного program ID, pinned program identity и load receipt, проверяет точный список карт и удаляет только известные pins. Неизвестные attachment, receipt или map pins блокируют очистку. Эти проверки и shell syntax покрыты offline-тестами, но они не доказывают поведение ядра.

Guest load, unload и policy update координируются одним root-owned `/run/lock/opla-xdp.lock`; lock удерживается на протяжении операции. Он сериализует только OPLA-команды. Внешний root-процесс, который меняет attachment или bpffs pins без этой блокировки, остаётся гонкой между проверкой и изменением. Поэтому перед live-проверкой требуется одиночный writer и отдельная проверка интерфейса. Unload снимает attachment только при совпадении interface program ID с load receipt и pinned program; карты очищаются только при совпадении receipt, pinned map IDs/types и program `map_ids`. При несовпадении ресурсы сохраняются для ручной сверки.

Новые load receipts используют schema 2 и связывают program ID/tag с `map_ids` и ID/type каждой из трёх ожидаемых карт. Для legacy receipt schema 1, где этой связи ещё нет, policy update и unload требуют заново прочитать pinned program и каждую ожидаемую map, а затем проверить, что live map IDs точно равны `program.map_ids`, program ID/tag совпадают с receipt и attachment ID совпадает с program. Это не переписывает старый receipt. Неполная/противоречивая инвентаризация блокирует действие и сохраняет ресурсы.

Внутри guest команды используют `sudo`; cloud-init выдаёт пользователю `student` полный sudo в гостевой ОС. Это не даёт доступ к host root, но guest root сам по себе не является границей доверия против компрометации `student`. Реальные native/generic attachment, verifier result, программа/maps IDs и detach проверяются только на разрешённом dedicated host. Portable C harness проверяет логику с mock maps/часами. Предельный pps и ускорение относительно netfilter не измерены. Автоматического GC HASH map нет.
