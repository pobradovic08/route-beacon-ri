-- Router metadata (populated from BMP Initiation messages).
-- May be empty until the ingester processes its first Initiation TLV.
CREATE TABLE IF NOT EXISTS routers (
    router_id   TEXT        PRIMARY KEY,
    router_ip   INET,
    hostname    TEXT,
    as_number   BIGINT,
    description TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Pre-aggregated route counts per router/table/AFI.
-- Refreshed periodically by the maintenance loop (REFRESH CONCURRENTLY).
CREATE MATERIALIZED VIEW IF NOT EXISTS route_summary AS
SELECT router_id,
       table_name,
       afi,
       COUNT(*)                AS route_count,
       COUNT(DISTINCT prefix)  AS unique_prefixes,
       COUNT(DISTINCT nexthop) AS unique_nexthops,
       MAX(updated_at)         AS last_update
FROM current_routes
GROUP BY router_id, table_name, afi;

-- Required for REFRESH MATERIALIZED VIEW CONCURRENTLY.
CREATE UNIQUE INDEX IF NOT EXISTS idx_route_summary_pk
    ON route_summary (router_id, table_name, afi);

-- Discover routers from all data sources, not just the routers table.
-- Ensures routers appear in listings even before BMP Initiation is processed.
CREATE OR REPLACE VIEW routers_overview AS
WITH known_routers AS (
    SELECT router_id FROM routers
    UNION
    SELECT DISTINCT router_id FROM rib_sync_status
    UNION
    SELECT DISTINCT router_id FROM current_routes
)
SELECT kr.router_id,
       r.router_ip,
       r.hostname,
       r.as_number,
       r.description,
       r.first_seen,
       r.last_seen,
       COALESCE(rs.route_count, 0)     AS route_count,
       COALESCE(rs.unique_prefixes, 0) AS unique_prefixes,
       s.eor_seen                      AS all_afis_synced,
       s.session_start_time,
       s.sync_updated_at
FROM known_routers kr
LEFT JOIN routers r ON r.router_id = kr.router_id
LEFT JOIN LATERAL (
    SELECT COUNT(*)              AS route_count,
           COUNT(DISTINCT prefix) AS unique_prefixes
    FROM current_routes cr
    WHERE cr.router_id = kr.router_id
) rs ON true
LEFT JOIN LATERAL (
    SELECT bool_and(eor_seen)        AS eor_seen,
           MAX(session_start_time)   AS session_start_time,
           MAX(updated_at)           AS sync_updated_at
    FROM rib_sync_status ss
    WHERE ss.router_id = kr.router_id
) s ON true;
