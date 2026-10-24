#!/usr/bin/env bash
set -euo pipefail
umask 077
destination="${1:?Specify a new backup directory}"
mkdir -m 700 "$destination"
docker exec opla-monitoring-db-1 pg_dump -U zabbix -d zabbix -Fc > "$destination/zabbix.dump.part"
docker exec -i opla-monitoring-db-1 pg_restore -l < "$destination/zabbix.dump.part" > "$destination/catalog.txt"
mv "$destination/zabbix.dump.part" "$destination/zabbix.dump"
(cd "$destination" && sha256sum zabbix.dump > SHA256SUMS)
echo "Backup: $destination. Restore must be verified in a separate database."
