# Backup and recovery

[Русский](backup-restore.md) · **English**

| Mechanism | Preserves | Does not guarantee |
|---|---|---|
| Git bundle / source archive | History or selected sources | VM RAM/disks, database or runtime secrets |
| QMP savevm | Supported RAM/disk state of one running VM | Atomic multi-VM and PostgreSQL consistency |
| Offline VM copy | Standalone qcow2, seed ISO, lab state | Network/launcher recreation or application correctness |
| pg_dump -Fc | PostgreSQL schema and data | VM state, SMTP/API secrets or email queue |
| Private configuration/queue copy | Configuration and pending jobs | Safe storage without encryption or exactly-once delivery |

An internal qcow2 snapshot is not an independent backup. Keep copies off the working disk and outside Git.

## Select the lab

```bash
export LAB_DIR="$(python3 bin/state.py --latest)"
printf '%s\n' "$LAB_DIR"
make monitoring-stop
```

Stop active test generation for a consistent experiment. Rollback changes clocks and counter epochs; stop monitoring before loadvm.

## QMP snapshots

```bash
make vm-save VM=client TAG=before-change
make vm-snapshots VM=client
```

Create a marker before saving, change it afterwards, and verify its original contents after:

```bash
make vm-load VM=client TAG=before-change ROLLBACK=yes
make ssh VM=client
```

Rollback discards changes after the snapshot and can interrupt SSH. Deleting a snapshot does not roll back the VM:

```bash
make vm-delete VM=client TAG=before-change
make monitoring-start
sudo python3 bin/vm-state.py status --lab "$LAB_DIR" --vm all
```

Operations on all VMs are sequential, not atomic. The launcher must expose QMP sockets.

## Offline disk backup

Use `make ssh VM=attacker`, `victim` and `client` separately and run `sudo shutdown -h now` in each. Once all QEMU processes exit:

```bash
lab_id="${LAB_DIR##*/}"
sudo systemctl show "qemu-$lab_id-attacker.service" \
  "qemu-$lab_id-victim.service" "qemu-$lab_id-client.service" \
  -p Id -p ActiveState -p MainPID
```

All MainPID values must be zero. Do not use `make down`: it deletes lab disks.

```bash
mkdir -p "$HOME/opla-backups"
disk_backup_dir="$HOME/opla-backups/disks-$(date +%Y%m%d-%H%M%S)"
make vm-backup BACKUP_DIR="$disk_backup_dir"
```

The backup contains standalone role disks, seed ISOs, state.env and a manifest with disk SHA-256. It rejects any running VM. `qemu-img check` validates qcow2 structure, not application state. Root-owned 0700 backups may require sudo to inspect.

```bash
make vm-resume
make ready
```

Check XDP attachment/scan mode, Suricata, HTTP and collector after boot. Resume needs the retained bridge/TAP/seed; it is not full host-reboot recovery.

## Restore one disk

Stop all VMs and the collector again. Select a known backup explicitly:

```bash
make vm-restore VM=victim BACKUP_DIR="$disk_backup_dir" ROLLBACK=yes
make vm-resume
make ready
```

Restore validates hashes/formats, stages the replacement and retains `disk.before-restore-*.qcow2`. It restores only one disk, not the whole network or seed ISO. Keep the previous disk until boot/services are accepted. BPF program IDs are not stable between runs.

## PostgreSQL backup and isolated restore drill

With the database running:

```bash
mkdir -p "$HOME/opla-backups"
db_backup_dir="$HOME/opla-backups/db-$(date +%Y%m%d-%H%M%S)"
make backup-db BACKUP_DIR="$db_backup_dir"
(cd "$db_backup_dir" && sha256sum -c SHA256SUMS)
bash tools/verify-db-backup.sh "$db_backup_dir"
```

Backup uses `opla-monitoring-db-1`, user/database zabbix. `catalog.txt` lists archive contents; SHA256SUMS validates zabbix.dump. This is not a raw Docker volume backup.

The drill uses the exact running PostgreSQL image ID, a temporary container with `--network none`, no published port and a read-only backup mount. It restores to a new `opla_restore` database with `pg_restore --exit-on-error`, checks hosts/items/triggers/dashboard, saves a private report and removes only its new container/anonymous volume by exact ID. It never mounts the working database volume. Counts include Zabbix defaults.

A failed hash/restore returns an error without automatically printing potentially sensitive restore output. SIGKILL or a Docker failure can bypass cleanup; inspect the temporary container ID rather than pruning globally.

This is not an automatic production database replacement. A real replacement needs service shutdown, a fresh rollback backup, PostgreSQL/role compatibility checks and an agreed recovery point.

## Configuration and source history

```bash
umask 077
mkdir -p "$HOME/opla-backups"
git bundle create "$HOME/opla-backups/source-$(date +%Y%m%d-%H%M%S).bundle" --all
```

Bundles omit uncommitted files. Encrypt separate copies of alerts.json, the email queue, monitoring/.env and private inventories. Stop opla-alerts.service before copying its queue; rolling it back can resend messages accepted after the backup point.

A successful backup requires a tested restore. Record date, source revision, hashes/manifest, tested recovery scenario and independent storage location.
