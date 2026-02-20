-- Enable btree_gist for GiST indexing on inet/cidr types
CREATE EXTENSION IF NOT EXISTS btree_gist;

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
    communities_std   TEXT[],
    communities_ext   TEXT[],
    communities_large TEXT[],
    attrs        JSONB,
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
