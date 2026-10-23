-- psql -v host_name='opla-lab-...' -f inspect.sql
-- Этот файл только читает данные. Фильтр по одному стенду обязателен.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT h.host, i.itemid, i.name, i.key_, i.value_type, i.status
FROM hosts h JOIN items i ON i.hostid=h.hostid
WHERE h.host=:'host_name' AND i.key_ LIKE 'xdp.%'
ORDER BY i.key_;

SELECT to_timestamp(v.clock) AT TIME ZONE 'Europe/Moscow' AS collected_msk,
       i.key_, v.value
FROM history_uint v JOIN items i ON i.itemid=v.itemid
JOIN hosts h ON h.hostid=i.hostid
WHERE h.host=:'host_name' AND i.key_ LIKE 'xdp.%'
  AND v.clock >= extract(epoch FROM now())::bigint-3600
ORDER BY v.clock DESC,v.ns DESC LIMIT 30;

SELECT to_timestamp(v.clock) AT TIME ZONE 'Europe/Moscow' AS collected_msk,
       i.key_,v.value
FROM history v JOIN items i ON i.itemid=v.itemid
JOIN hosts h ON h.hostid=i.hostid
WHERE h.host=:'host_name' AND i.key_ LIKE 'xdp.%.rate'
  AND v.clock >= extract(epoch FROM now())::bigint-3600
ORDER BY v.clock DESC,v.ns DESC LIMIT 30;

SELECT to_timestamp(v.clock) AT TIME ZONE 'Europe/Moscow' AS collected_msk,
       v.value
FROM history_log v JOIN items i ON i.itemid=v.itemid
JOIN hosts h ON h.hostid=i.hostid
WHERE h.host=:'host_name' AND i.key_='xdp.events'
  AND v.clock >= extract(epoch FROM now())::bigint-3600
ORDER BY v.clock DESC,v.ns DESC LIMIT 20;
COMMIT;
