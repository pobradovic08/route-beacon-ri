-- Operator-provided router metadata (display name, location).
ALTER TABLE routers ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS location TEXT;

-- Recreate routers_overview to include the new columns.
-- DROP required because CREATE OR REPLACE cannot change column names/order.
DROP VIEW IF EXISTS routers_overview;
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
       r.display_name,
       r.location,
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
