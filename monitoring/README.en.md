# Monitoring

[Русский](README.md) · **English**

See the [root README](../README.md#zabbix) for startup.

Sources are pinned BPF maps, sysfs, nginx JSON logs/probes, Suricata EVE and the passive scan detector. The host bridge reads through SSH and sends to the Zabbix trapper. API credentials are for provisioning, not the collector.

`catalog.py` defines 34 raw values and 15 rates: 49 items total. Provisioning manages 23 triggers, 5 graphs and a five-page dashboard. Repeat setup repairs managed objects. Clone dashboards under another name for personal changes. `policy.json` does not change XDP or nginx prevention thresholds.

```bash
make monitoring-stop
python3 monitoring/diagnose.py --lab "$LAB_DIR"
make monitoring-start
```

Diagnostics and the collector share a lock. Check Latest data timestamps and counter deltas; rates require new samples. `xdp.loaded=1` is a boolean for an attached program. Capture/sysfs counters do not fully account for native XDP drops.

SQL under `sql/` reads the database. Runtime, `.env` and credentials stay outside Git. Web/trapper bind to localhost 8080/10051; PostgreSQL has no published host port. Do not delete its volume to repair a graph.

Gmail/Proton alerts use `alert_delivery.py` and `alerts_service.py`; private configuration is `~/.config/opla/alerts.json`, queue state is `~/.local/state/opla-alerts/`. They share Gmail/Tor SMTP transport. `configure-mail.py` provisions native Zabbix email instead; enabling both intentionally duplicates delivery.
