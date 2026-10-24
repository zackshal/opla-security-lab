-- psql -v host_name='opla-lab-...' < security-overview.sql
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT h.host, i.itemid, i.key_, i.name, i.value_type, i.status
FROM hosts h JOIN items i ON i.hostid=h.hostid
WHERE h.host=:'host_name' AND (i.key_ LIKE 'xdp.%' OR i.key_ LIKE 'http.%' OR i.key_ LIKE 'net.%')
ORDER BY i.key_;

SELECT i.key_,
       to_timestamp(greatest(u.clock,n.clock,s.clock,l.clock)) AT TIME ZONE 'Europe/Moscow' AS last_seen_msk,
       coalesce(u.value::text,n.value::text,s.value,l.value) AS latest_value
FROM hosts h JOIN items i ON i.hostid=h.hostid
LEFT JOIN LATERAL (
    SELECT v.clock,v.value FROM history_uint v
    WHERE v.itemid=i.itemid AND i.value_type=3
    ORDER BY v.clock DESC,v.ns DESC LIMIT 1
) u ON true
LEFT JOIN LATERAL (
    SELECT v.clock,v.value FROM history v
    WHERE v.itemid=i.itemid AND i.value_type=0
    ORDER BY v.clock DESC,v.ns DESC LIMIT 1
) n ON true
LEFT JOIN LATERAL (
    SELECT v.clock,v.value FROM history_str v
    WHERE v.itemid=i.itemid AND i.value_type=1
    ORDER BY v.clock DESC,v.ns DESC LIMIT 1
) s ON true
LEFT JOIN LATERAL (
    SELECT v.clock,v.value FROM history_log v
    WHERE v.itemid=i.itemid AND i.value_type=2
    ORDER BY v.clock DESC,v.ns DESC LIMIT 1
) l ON true
WHERE h.host=:'host_name' AND (i.key_ LIKE 'xdp.%' OR i.key_ LIKE 'http.%' OR i.key_ LIKE 'net.%')
ORDER BY i.key_;
COMMIT;
