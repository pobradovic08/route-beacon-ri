-- Router metadata table (populated from BMP Initiation messages)
CREATE TABLE IF NOT EXISTS routers (
    router_id    TEXT PRIMARY KEY,
    router_ip    INET,
    hostname     TEXT,
    as_number    BIGINT,
    description  TEXT,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- New columns on current_routes
ALTER TABLE current_routes ADD COLUMN IF NOT EXISTS origin_asn INTEGER;
ALTER TABLE current_routes ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ NOT NULL DEFAULT now();

-- New column on route_events
ALTER TABLE route_events ADD COLUMN IF NOT EXISTS origin_asn INTEGER;

-- GIN indexes for community filtering
CREATE INDEX IF NOT EXISTS idx_current_routes_comm_std_gin
    ON current_routes USING GIN (communities_std);
CREATE INDEX IF NOT EXISTS idx_current_routes_comm_ext_gin
    ON current_routes USING GIN (communities_ext);
CREATE INDEX IF NOT EXISTS idx_current_routes_comm_large_gin
    ON current_routes USING GIN (communities_large);

-- Origin AS lookup
CREATE INDEX IF NOT EXISTS idx_current_routes_origin_asn
    ON current_routes (origin_asn);

-- Exact prefix lookup (B-tree, complements existing GiST for LPM)
CREATE INDEX IF NOT EXISTS idx_current_routes_prefix_btree
    ON current_routes (prefix);

-- Recently changed routes / polling support
CREATE INDEX IF NOT EXISTS idx_current_routes_updated_at
    ON current_routes (updated_at DESC);

-- Cross-router RIB comparison joins
CREATE INDEX IF NOT EXISTS idx_current_routes_comparison
    ON current_routes (table_name, afi, prefix, router_id);

-- Next-hop grouping
CREATE INDEX IF NOT EXISTS idx_current_routes_nexthop
    ON current_routes (nexthop);

-- Route count summary (materialized view)
CREATE MATERIALIZED VIEW IF NOT EXISTS route_summary AS
SELECT router_id, table_name, afi,
       COUNT(*) AS route_count,
       COUNT(DISTINCT prefix) AS unique_prefixes,
       COUNT(DISTINCT nexthop) AS unique_nexthops,
       MAX(updated_at) AS last_update
FROM current_routes
GROUP BY router_id, table_name, afi;

CREATE UNIQUE INDEX IF NOT EXISTS idx_route_summary_pk
    ON route_summary (router_id, table_name, afi);
