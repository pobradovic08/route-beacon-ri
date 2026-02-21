-- Enable btree_gist for GiST indexing on inet/cidr types
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- Router metadata (populated from BMP Initiation messages)
CREATE TABLE IF NOT EXISTS routers (
    router_id    TEXT PRIMARY KEY,
    router_ip    INET,
    hostname     TEXT,
    as_number    BIGINT,
    description  TEXT,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Current Loc-RIB state
CREATE TABLE IF NOT EXISTS current_routes (
    router_id    TEXT        NOT NULL,
    table_name   TEXT        NOT NULL,
    afi          SMALLINT    NOT NULL CHECK (afi IN (4, 6)),
    prefix       CIDR        NOT NULL,
    path_id      BIGINT      NOT NULL DEFAULT 0,
    nexthop      INET,
    as_path      TEXT,
    origin       TEXT,
    localpref    INTEGER,
    med          INTEGER,
    origin_asn   INTEGER,
    communities_std   TEXT[],
    communities_ext   TEXT[],
    communities_large TEXT[],
    attrs        JSONB,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (router_id, table_name, afi, prefix, path_id)
);

-- Route events history (partitioned by day)
CREATE TABLE IF NOT EXISTS route_events (
    event_id     BYTEA       NOT NULL,
    ingest_time  TIMESTAMPTZ NOT NULL,
    router_id    TEXT        NOT NULL,
    table_name   TEXT        NOT NULL,
    afi          SMALLINT    NOT NULL CHECK (afi IN (4, 6)),
    prefix       CIDR        NOT NULL,
    path_id      BIGINT,
    action       CHAR(1)     NOT NULL CHECK (action IN ('A', 'D')),
    nexthop      INET,
    as_path      TEXT,
    origin       TEXT,
    localpref    INTEGER,
    med          INTEGER,
    origin_asn   INTEGER,
    communities_std   TEXT[],
    communities_ext   TEXT[],
    communities_large TEXT[],
    attrs        JSONB,
    bmp_raw      BYTEA,
    PRIMARY KEY (event_id, ingest_time)
) PARTITION BY RANGE (ingest_time);

-- Sync status
CREATE TABLE IF NOT EXISTS rib_sync_status (
    router_id          TEXT        NOT NULL,
    table_name         TEXT        NOT NULL,
    afi                SMALLINT    NOT NULL CHECK (afi IN (4, 6)),
    last_parsed_msg_time TIMESTAMPTZ,
    last_raw_msg_time    TIMESTAMPTZ,
    eor_seen           BOOLEAN     NOT NULL DEFAULT false,
    eor_time           TIMESTAMPTZ,
    session_start_time TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (router_id, table_name, afi)
);

-- Indexes: current_routes
CREATE INDEX IF NOT EXISTS idx_current_routes_prefix_gist
    ON current_routes USING GIST (prefix inet_ops);
CREATE INDEX IF NOT EXISTS idx_current_routes_router_table_afi
    ON current_routes (router_id, table_name, afi);
CREATE INDEX IF NOT EXISTS idx_current_routes_comm_std_gin
    ON current_routes USING GIN (communities_std);
CREATE INDEX IF NOT EXISTS idx_current_routes_comm_ext_gin
    ON current_routes USING GIN (communities_ext);
CREATE INDEX IF NOT EXISTS idx_current_routes_comm_large_gin
    ON current_routes USING GIN (communities_large);
CREATE INDEX IF NOT EXISTS idx_current_routes_origin_asn
    ON current_routes (origin_asn);
CREATE INDEX IF NOT EXISTS idx_current_routes_prefix_btree
    ON current_routes (prefix);
CREATE INDEX IF NOT EXISTS idx_current_routes_updated_at
    ON current_routes (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_current_routes_comparison
    ON current_routes (table_name, afi, prefix, router_id);
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
