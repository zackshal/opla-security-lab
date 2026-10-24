-- Средняя и максимальная наблюдаемая скорость по 10-секундным корзинам.
-- Это агрегация снимков метрик, а не индивидуальных пакетов PCAP.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT to_timestamp((v.clock/10)*10) AT TIME ZONE 'Europe/Moscow' AS bucket_msk,
       i.key_,count(*) AS samples,
       round(avg(v.value)::numeric,2) AS average_pps,
       round(max(v.value)::numeric,2) AS maximum_pps
FROM history v JOIN items i ON i.itemid=v.itemid
JOIN hosts h ON h.hostid=i.hostid
WHERE h.host=:'host_name'
  AND i.key_ IN ('xdp.syn.rate','xdp.pass.rate','xdp.drop.rate')
  AND v.clock >= extract(epoch FROM now())::bigint-3600
GROUP BY (v.clock/10)*10,i.key_
ORDER BY (v.clock/10)*10 DESC,i.key_;
COMMIT;
