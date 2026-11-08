# Dual-NIC topology

`ens3` — management path, `ens4` — isolated lab/data path. Гостевые роли имеют
отдельные management и data интерфейсы; management SSH не должен использовать
экспериментальный data-маршрут. nftables допускает только явно описанные
направления, а ресурсы создаются с ownership receipt и удаляются fail-closed.

Это статический контракт. Live bridge/TAP/routes/nft evidence остаётся
`NOT TESTED`, пока не выполнен dedicated-host acceptance.
