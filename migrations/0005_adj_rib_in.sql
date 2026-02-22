-- =============================================================================
-- Migration 0005: Adj-RIB-In route storage
-- Feature: 008-adj-rib-in
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. New table: adj_rib_in
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS adj_rib_in (
    router_id        TEXT        NOT NULL,
    peer_address     INET        NOT NULL,
    peer_asn         BIGINT      NOT NULL,
    peer_bgp_id      TEXT        NOT NULL DEFAULT '',
    is_post_policy   BOOLEAN     NOT NULL,
    table_name       TEXT        NOT NULL,
    afi              SMALLINT    NOT NULL CHECK (afi IN (4, 6)),
    prefix           CIDR        NOT NULL,
    path_id          BIGINT      NOT NULL DEFAULT 0,
    nexthop          INET,
    as_path          TEXT,
    origin           TEXT,
    localpref        INTEGER,
    med              INTEGER,
    origin_asn       INTEGER,
    communities_std   TEXT[],
    communities_ext   TEXT[],
    communities_large TEXT[],
    attrs            JSONB,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (router_id, peer_address, is_post_policy, table_name, afi, prefix, path_id)
);

-- ---------------------------------------------------------------------------
-- 2. New table: adj_rib_in_sync_status
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS adj_rib_in_sync_status (
    router_id          TEXT        NOT NULL,
    peer_address       INET        NOT NULL,
    afi                SMALLINT    NOT NULL CHECK (afi IN (4, 6)),
    session_start_time TIMESTAMPTZ,
    eor_seen           BOOLEAN     NOT NULL DEFAULT false,
    eor_time           TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (router_id, peer_address, afi)
);

-- ---------------------------------------------------------------------------
-- 3. Indexes: adj_rib_in
-- ---------------------------------------------------------------------------

-- Prefix lookup (GiST for containment, B-tree for equality)
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_prefix_gist
    ON adj_rib_in USING GIST (prefix inet_ops);
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_prefix_btree
    ON adj_rib_in (prefix);

-- Peer lookup + Peer Down deletion
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_router_peer
    ON adj_rib_in (router_id, peer_address);

-- Router lookup + session termination deletion
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_router_table_afi
    ON adj_rib_in (router_id, table_name, afi);

-- Community GIN indexes
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_comm_std_gin
    ON adj_rib_in USING GIN (communities_std);
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_comm_ext_gin
    ON adj_rib_in USING GIN (communities_ext);
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_comm_large_gin
    ON adj_rib_in USING GIN (communities_large);

-- Additional B-tree indexes
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_origin_asn
    ON adj_rib_in (origin_asn);
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_nexthop
    ON adj_rib_in (nexthop);
CREATE INDEX IF NOT EXISTS idx_adj_rib_in_updated_at
    ON adj_rib_in (updated_at DESC);

-- ---------------------------------------------------------------------------
-- 4. Alter route_events: add peer columns for Adj-RIB-In history
-- ---------------------------------------------------------------------------
ALTER TABLE route_events ADD COLUMN IF NOT EXISTS peer_address   INET;
ALTER TABLE route_events ADD COLUMN IF NOT EXISTS peer_asn       BIGINT;
ALTER TABLE route_events ADD COLUMN IF NOT EXISTS peer_bgp_id    TEXT;
ALTER TABLE route_events ADD COLUMN IF NOT EXISTS is_post_policy BOOLEAN;

-- ---------------------------------------------------------------------------
-- 5. Materialized view: adj_rib_in_summary
-- ---------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS adj_rib_in_summary AS
SELECT router_id,
       peer_address,
       peer_asn,
       is_post_policy,
       table_name,
       afi,
       COUNT(*)                AS route_count,
       COUNT(DISTINCT prefix)  AS unique_prefixes,
       COUNT(DISTINCT nexthop) AS unique_nexthops,
       MAX(updated_at)         AS last_update
FROM adj_rib_in
GROUP BY router_id, peer_address, peer_asn, is_post_policy, table_name, afi;

CREATE UNIQUE INDEX IF NOT EXISTS idx_adj_rib_in_summary_pk
    ON adj_rib_in_summary (router_id, peer_address, is_post_policy, table_name, afi);

-- ---------------------------------------------------------------------------
-- 6. View: peers_overview
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW peers_overview AS
SELECT a.router_id,
       r.hostname                                          AS router_hostname,
       a.peer_address,
       a.peer_asn,
       a.peer_bgp_id,
       COUNT(*) FILTER (WHERE NOT a.is_post_policy)        AS pre_policy_routes,
       COUNT(*) FILTER (WHERE a.is_post_policy)            AS post_policy_routes,
       COUNT(*)                                            AS total_routes,
       COUNT(DISTINCT a.prefix)                            AS unique_prefixes,
       MAX(a.updated_at)                                   AS last_update
FROM adj_rib_in a
LEFT JOIN routers r ON r.router_id = a.router_id
GROUP BY a.router_id, r.hostname, a.peer_address, a.peer_asn, a.peer_bgp_id;

-- ---------------------------------------------------------------------------
-- 7. Recreate routers_overview with Adj-RIB-In counts
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW routers_overview AS
WITH known_routers AS (
    SELECT router_id FROM routers
    UNION
    SELECT DISTINCT router_id FROM rib_sync_status
    UNION
    SELECT DISTINCT router_id FROM current_routes
    UNION
    SELECT DISTINCT router_id FROM adj_rib_in
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
       COALESCE(rs.route_count, 0)         AS route_count,
       COALESCE(rs.unique_prefixes, 0)     AS unique_prefixes,
       COALESCE(adj.adj_route_count, 0)    AS adj_rib_in_route_count,
       COALESCE(adj.adj_peer_count, 0)     AS adj_rib_in_peer_count,
       s.eor_seen                          AS all_afis_synced,
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
    SELECT COUNT(*)                        AS adj_route_count,
           COUNT(DISTINCT peer_address)    AS adj_peer_count
    FROM adj_rib_in ar
    WHERE ar.router_id = kr.router_id
) adj ON true
LEFT JOIN LATERAL (
    SELECT bool_and(eor_seen)        AS eor_seen,
           MAX(session_start_time)   AS session_start_time,
           MAX(updated_at)           AS sync_updated_at
    FROM rib_sync_status ss
    WHERE ss.router_id = kr.router_id
) s ON true;
