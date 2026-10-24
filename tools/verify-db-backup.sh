#!/usr/bin/env bash
set -euo pipefail
umask 077
backup_dir="$(realpath -- "${1:?Specify a PostgreSQL backup directory}")"
[[ -f "$backup_dir/zabbix.dump" && -f "$backup_dir/SHA256SUMS" ]]
(cd "$backup_dir" && sha256sum -c SHA256SUMS)
image_id="$(docker inspect --format '{{.Image}}' opla-monitoring-db-1)"
test_password="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
report_dir="${OPLA_RESTORE_REPORT_DIR:-reports}"
mkdir -p "$report_dir"
report_file="$report_dir/db-restore-$(date +%Y%m%d-%H%M%S)-$$.log"
container_id="$(docker run -d --network none --memory 512m --cpus 1 \
  --env "POSTGRES_PASSWORD=$test_password" \
  --mount "type=bind,src=$backup_dir,dst=/backup,readonly" "$image_id")"
cleanup() { docker rm -fv "$container_id" >/dev/null; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ready=0
for attempt in {1..60}; do
  if docker exec "$container_id" pg_isready -U postgres >/dev/null 2>&1; then
    ready=1;break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then
  docker logs "$container_id" > "$report_file" 2>&1
  echo "Temporary PostgreSQL did not become ready; private log: $report_file" >&2
  exit 1
fi
docker exec "$container_id" createdb -U postgres opla_restore
if ! docker exec "$container_id" pg_restore -U postgres -d opla_restore \
  --exit-on-error --no-owner --no-privileges /backup/zabbix.dump > "$report_file" 2>&1; then
  echo "Restore failed; inspect private log locally: $report_file" >&2
  exit 1
fi
docker exec "$container_id" psql -X -U postgres -d opla_restore -v ON_ERROR_STOP=1 \
  -c "SELECT 'hosts' AS object, count(*) FROM hosts
      UNION ALL SELECT 'items', count(*) FROM items
      UNION ALL SELECT 'triggers', count(*) FROM triggers
      UNION ALL SELECT 'dashboards', count(*) FROM dashboard;" | tee -a "$report_file"
echo "PASS: restore into a separate isolated database; report: $report_file"
