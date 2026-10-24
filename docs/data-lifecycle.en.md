# Stop, retain or delete data

[Русский](data-lifecycle.md) · **English**

| Action | Result |
|---|---|
| Stop collector / alerts | Retains VMs and database |
| Gracefully shut down VMs | Retains disks/snapshots; resume needs retained networking |
| `make monitoring-down` | Removes monitoring containers; retains database volume |
| `make down` | Deletes the selected lab, working disks and internal snapshots |
| Compose `down --volumes` | Also deletes that project's database volume |
| Remove images/backups | May destroy backing dependencies or the only recovery copy |

These instructions target OPLA only. File deletion is not guaranteed secure erasure on SSDs/snapshots/backups. Revoking credentials is separate from deleting local copies.

## Locations

| Location | Contents |
|---|---|
| `/var/lib/opla/lab-*` | Working disks, seed ISOs, state, QMP sockets and internal snapshots |
| `images/` | Base/role images, potentially referenced by working disks |
| `monitoring/.env` | Database password and image tags |
| `monitoring/runtime/` | Provisioning metadata and collector state/events |
| `reports/`, `dumps/` | Experiment output and possible captures |
| `opla-monitoring_db-data` | Database volume; verify its actual name |
| `~/.config/opla/alerts.json` | SMTP password, addresses and API token |
| `~/.local/state/opla-alerts/` | Email queue and polling cursor |
| `~/.config/opla/gitlab-runner/` | Runner authentication/configuration |
| `~/.config/opla/tor-bridges/` | Bridge feed/configuration and timer helper |
| `~/opla-backups`, `~/opla-archive`, `~/opla-transfer` | Backups, quarantined inputs and exported sources |

## Stop observation

```bash
make monitoring-stop
systemctl --user stop opla-alerts.service
```

This retains queue, secrets and DB. To remove the email unit:

```bash
python3 monitoring/alerts_service.py remove
```

Configuration/queue remain. Check an already absent unit before repeating removal.

## Retain VMs or delete one lab

For retention use graceful guest shutdown, verify MainPID=0 and follow [backup](backup-restore.en.md). For deliberate deletion after backup:

```bash
export LAB_DIR="$(python3 bin/state.py --latest)"
printf 'Lab to delete: %s\n' "$LAB_DIR"
python3 bin/state.py "$LAB_DIR" LAB_ID
make down LAB_DIR="$LAB_DIR"
```

Cleanup stops that lab's QEMU/DHCP, removes its TAP/bridge and owned nftables table, then deletes LAB_DIR. Select instances individually; never remove all of /var/lib or flush the firewall. Use an explicit lab path instead of latest when several exist.

## Monitoring and database

Retain the database:

```bash
make monitoring-down
```

For deliberate database destruction, first create a dump and run the isolated restore drill. Stop collector/alerts and inspect the volume:

```bash
docker inspect opla-monitoring-db-1 --format '{{json .Mounts}}'
```

If the container is gone, use volume ls/inspect and verify `com.docker.compose.project=opla-monitoring`. From the intended checkout only:

```bash
docker compose --env-file monitoring/.env -f monitoring/compose.yaml down --volumes
```

This removes this project's volumes, including the database. Do not use global Docker prune. The Compose project name is fixed in compose.yaml; check for another checkout using the same name.

## Reports, archives and images

```bash
du -sh reports dumps images "$HOME/opla-backups" "$HOME/opla-archive" "$HOME/opla-transfer"
git status --short
git clean -ndX
```

Some paths may not exist. The final command is inspection only, not permission to run `git clean -fdX/-fdx`; ignored files can contain secrets and active images. Remove individually verified paths using `rm -i` or `rm -rI`. Retain images/.gitkeep and dumps/.gitkeep.

Before deleting qcow2 images, inventory every retained lab and inspect stopped disks with `qemu-img info --backing-chain`. A stopped disk may still depend on a base image. Removing one lab does not establish that the image is unused elsewhere.

Keep independent tested backups and more than one generation. Downloads, ~/vim and transfer archives are separate from Git checkouts.

## Email secrets

After stopping the service:

```bash
rm -i -- "$HOME/.config/opla/alerts.json"
rm -rI -- "$HOME/.local/state/opla-alerts"
```

Deleting queue state resets deduplication and cursors; active problems can be resent after reconfiguration. Revoke the Gmail app password and Zabbix API token for permanent retirement. These commands do not delete mail from inboxes or old backups.

## Separate local Runner / Tor toolkit

In the separate local-runner directory, pause jobs and wait for active work to finish:

```bash
cd ~/vim/opla-local-runner
python3 runner.py pause
```

Stop only its Compose project, retaining Tor state:

```bash
python3 - <<'INNER'
import json
import runner
reference = json.loads((runner.STATE/'image.json').read_text())['reference']
runner.compose(['down'], reference)
INNER
```

Use down --volumes only for intentional deletion of that project's state. Do not stop the host Tor used by other applications. Runner registration and access-token revocation are separate.

```bash
systemctl --user disable --now opla-tor-bridges.timer
sudo systemctl disable --now opla-ci-firewall.timer
sudo systemctl disable opla-ci-firewall.service
sudo /usr/sbin/nft flush chain inet filter opla_ci_forward
```

The last commands disable the CI egress exception. Do not delete a referenced chain. Remove helper/config/unit files individually only after checking other forwarding users; never automatically set global ip_forward=0.

## Dedicated-server profile

Back up server data/configuration. Remove the owned NFQUEUE through the manager before stopping services:

```bash
sudo python3 /opt/opla/security/suricata/manage.py off
sudo systemctl disable --now opla-telemetry.service opla-xdp.service
```

XDP ExecStop refuses to detach a foreign program. Server pins live under `/sys/fs/bpf/opla-server`. Do not automatically uninstall system nginx/Suricata or restore an unknown earlier configuration. Remove /opt/opla, telemetry state/logs and /etc/opla-suricata only after service shutdown and backup review. There is no universally safe uninstall-everything playbook. Local cleanup does not delete hosted repositories.
