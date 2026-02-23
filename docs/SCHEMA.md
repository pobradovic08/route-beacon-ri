# PostgreSQL Schema Reference

Database used by the `rib-ingester` service. The API layer reads from these tables — the ingester is the sole writer.

**PostgreSQL version:** 16
**Required extension:** `btree_gist` (for GiST indexing on `inet`/`cidr` types)
**Migrations:** `migrations/0001_init.sql`, `0003_routers.sql`, `0004_router_metadata.sql`, `0005_adj_rib_in.sql`

---

## Tables

### `routers`

Router metadata populated from BMP Peer Up messages (Sent OPEN BGP Identifier and ASN) and operator-provided config (display name, location). One row per monitored router. Updated each time the ingester processes a Peer Up message.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `router_id` | `TEXT` | **PK** | — | Router identifier. The BGP Router ID from the Sent OPEN message (e.g. `10.0.0.2`). |
| `router_ip` | `INET` | yes | `NULL` | IP address the router connected from. |
| `hostname` | `TEXT` | yes | `NULL` | From BMP Initiation TLV type 2 (`sysName`). |
| `as_number` | `BIGINT` | yes | `NULL` | Router's autonomous system number (from Peer Up Sent OPEN). |
| `description` | `TEXT` | yes | `NULL` | From BMP Initiation TLV type 1 (`sysDescr`). |
| `display_name` | `TEXT` | yes | `NULL` | Operator-provided display name (from config file). |
| `location` | `TEXT` | yes | `NULL` | Operator-provided location (from config file). |
| `first_seen` | `TIMESTAMPTZ` | no | `now()` | When this router was first observed. Never overwritten on update. |
| `last_seen` | `TIMESTAMPTZ` | no | `now()` | Last BMP Peer Up received. Updated on every new session. |

**Upsert behavior:** `ON CONFLICT (router_id)` updates `router_ip`, `hostname`, `as_number`, `description`, `display_name`, `location` (using `COALESCE` to preserve non-null values) and sets `last_seen = now()`. `first_seen` is never overwritten.

---

### `current_routes`

Current Loc-RIB state — one row per active route. This is the primary table for the API to query "what routes exist right now." The ingester upserts on add and deletes on withdraw. Stale routes are purged after End-of-RIB (EOR) markers.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `router_id` | `TEXT` | **PK** | — | FK-like reference to `routers.router_id`. |
| `table_name` | `TEXT` | **PK** | — | BMP table name from TLV type 0. `"UNKNOWN"` if not provided by the router. |
| `afi` | `SMALLINT` | **PK** | — | Address family: `4` = IPv4, `6` = IPv6. CHECK constraint enforces these values. |
| `prefix` | `CIDR` | **PK** | — | Network prefix in CIDR notation (e.g. `10.100.0.0/24`, `2001:db8::/32`). |
| `path_id` | `BIGINT` | **PK** | `0` | BGP Add-Path path identifier. `0` when Add-Path is not in use. |
| `nexthop` | `INET` | yes | `NULL` | BGP next-hop address. |
| `as_path` | `TEXT` | yes | `NULL` | Space-delimited AS path (e.g. `"64496 65001 65002"`). AS_SETs appear as `{AS1,AS2}`. |
| `origin` | `TEXT` | yes | `NULL` | BGP origin attribute: `"IGP"`, `"EGP"`, or `"INCOMPLETE"`. |
| `localpref` | `INTEGER` | yes | `NULL` | LOCAL_PREF value. Typically `100` for iBGP routes. |
| `med` | `INTEGER` | yes | `NULL` | Multi-Exit Discriminator. |
| `origin_asn` | `INTEGER` | yes | `NULL` | Last ASN in `as_path` (the origin AS). `NULL` if `as_path` is empty or ends with an AS_SET. Derived by the ingester, not a raw BGP attribute. |
| `communities_std` | `TEXT[]` | yes | `NULL` | Standard BGP communities in `ASN:value` format (e.g. `{65001:100,65001:200}`). |
| `communities_ext` | `TEXT[]` | yes | `NULL` | Extended communities. Route Targets as `RT:ASN:value`, Route Origin as `SOO:ASN:value`. Unknown types fall back to hex. |
| `communities_large` | `TEXT[]` | yes | `NULL` | Large BGP communities in `GA:LD1:LD2` format. |
| `attrs` | `JSONB` | yes | `NULL` | Catch-all for any BGP path attributes not mapped to dedicated columns. `NULL` when no extra attributes are present. |
| `first_seen` | `TIMESTAMPTZ` | no | `now()` | When this route was first inserted. Preserved across upserts — never overwritten on conflict. |
| `updated_at` | `TIMESTAMPTZ` | no | `now()` | Last time this route was inserted or updated. Set to `now()` on every upsert. |

**Primary key:** `(router_id, table_name, afi, prefix, path_id)`

**Upsert behavior:** `ON CONFLICT` updates all attribute columns and sets `updated_at = now()`. `first_seen` is deliberately excluded from the UPDATE clause to preserve the original insertion timestamp.

**Deletion:** Routes are deleted on BGP withdraw (`action = 'D'`), on EOR stale-route purge (`updated_at < session_start_time`), and on session termination (all routes for the router/table removed).

#### Indexes

| Index | Type | Columns | Use Case |
|-------|------|---------|----------|
| `idx_current_routes_prefix_gist` | GiST (`inet_ops`) | `prefix` | Longest-prefix match (LPM) queries: `WHERE prefix >>= '10.1.2.3/32'` |
| `idx_current_routes_prefix_btree` | B-tree | `prefix` | Exact prefix lookups: `WHERE prefix = '10.100.0.0/24'` |
| `idx_current_routes_router_table_afi` | B-tree | `(router_id, table_name, afi)` | Per-router RIB queries, EOR stale-route purge |
| `idx_current_routes_origin_asn` | B-tree | `origin_asn` | "Show all routes originated by AS 65001" |
| `idx_current_routes_nexthop` | B-tree | `nexthop` | Next-hop grouping / "what prefixes use this nexthop?" |
| `idx_current_routes_updated_at` | B-tree DESC | `updated_at` | Recently changed routes, polling/pagination support |
| `idx_current_routes_comparison` | B-tree | `(table_name, afi, prefix, router_id)` | Cross-router RIB comparison ("which routers have this prefix?") |
| `idx_current_routes_comm_std_gin` | GIN | `communities_std` | Filter by standard community: `WHERE communities_std @> ARRAY['65001:100']` |
| `idx_current_routes_comm_ext_gin` | GIN | `communities_ext` | Filter by extended community: `WHERE communities_ext @> ARRAY['RT:64496:100']` |
| `idx_current_routes_comm_large_gin` | GIN | `communities_large` | Filter by large community |

---

### `adj_rib_in`

Per-peer Adj-RIB-In state — one row per route received from each BGP neighbor. Unlike `current_routes` (which stores only the best path selected by the router), this table stores **all candidate routes from every peer**, including pre-policy and post-policy views. The ingester upserts on add, deletes on withdraw, and removes all routes for a peer on BMP Peer Down.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `router_id` | `TEXT` | **PK** | — | FK-like reference to `routers.router_id`. The BMP speaker. |
| `peer_address` | `INET` | **PK** | — | IP address of the BGP neighbor that sent this route. |
| `peer_asn` | `BIGINT` | no | — | Autonomous system number of the BGP neighbor. |
| `peer_bgp_id` | `TEXT` | no | `''` | BGP identifier of the peer (from the BMP per-peer header). Empty string if unavailable. |
| `is_post_policy` | `BOOLEAN` | **PK** | — | `false` = pre-policy (Adj-RIB-In, peer type 0), `true` = post-policy (Adj-RIB-In-Post, peer type 1). |
| `table_name` | `TEXT` | **PK** | — | BMP table name. |
| `afi` | `SMALLINT` | **PK** | — | Address family: `4` = IPv4, `6` = IPv6. CHECK constraint enforces these values. |
| `prefix` | `CIDR` | **PK** | — | Network prefix in CIDR notation. |
| `path_id` | `BIGINT` | **PK** | `0` | BGP Add-Path path identifier. `0` when Add-Path is not in use. |
| `nexthop` | `INET` | yes | `NULL` | BGP next-hop address. |
| `as_path` | `TEXT` | yes | `NULL` | Space-delimited AS path. |
| `origin` | `TEXT` | yes | `NULL` | BGP origin attribute: `"IGP"`, `"EGP"`, or `"INCOMPLETE"`. |
| `localpref` | `INTEGER` | yes | `NULL` | LOCAL_PREF value. |
| `med` | `INTEGER` | yes | `NULL` | Multi-Exit Discriminator. |
| `origin_asn` | `INTEGER` | yes | `NULL` | Last ASN in `as_path` (the origin AS). Derived by the ingester. |
| `communities_std` | `TEXT[]` | yes | `NULL` | Standard BGP communities in `ASN:value` format. |
| `communities_ext` | `TEXT[]` | yes | `NULL` | Extended communities. |
| `communities_large` | `TEXT[]` | yes | `NULL` | Large BGP communities. |
| `attrs` | `JSONB` | yes | `NULL` | Extra BGP path attributes not mapped to dedicated columns. |
| `first_seen` | `TIMESTAMPTZ` | no | `now()` | When this route was first inserted. Preserved across upserts. |
| `updated_at` | `TIMESTAMPTZ` | no | `now()` | Last time this route was inserted or updated. |

**Primary key:** `(router_id, peer_address, is_post_policy, table_name, afi, prefix, path_id)`

**Upsert behavior:** `ON CONFLICT` updates all attribute columns and sets `updated_at = now()`. `first_seen` is preserved.

**Deletion:**
- BGP withdraw (`action = 'D'`): deletes the specific route by full PK.
- BMP Peer Down: deletes **all** routes for that `(router_id, peer_address)` pair.
- BMP session termination: deletes **all** `adj_rib_in` rows for that `router_id`.

#### Indexes

| Index | Type | Columns | Use Case |
|-------|------|---------|----------|
| `idx_adj_rib_in_prefix_gist` | GiST (`inet_ops`) | `prefix` | Subnet containment queries: `WHERE prefix >>= '10.1.2.3/32'` |
| `idx_adj_rib_in_prefix_btree` | B-tree | `prefix` | Exact prefix lookups across all peers |
| `idx_adj_rib_in_router_peer` | B-tree | `(router_id, peer_address)` | Per-peer route listing, Peer Down bulk deletion |
| `idx_adj_rib_in_router_table_afi` | B-tree | `(router_id, table_name, afi)` | Per-router lookups, session termination deletion |
| `idx_adj_rib_in_comm_std_gin` | GIN | `communities_std` | Filter by standard community |
| `idx_adj_rib_in_comm_ext_gin` | GIN | `communities_ext` | Filter by extended community |
| `idx_adj_rib_in_comm_large_gin` | GIN | `communities_large` | Filter by large community |
| `idx_adj_rib_in_origin_asn` | B-tree | `origin_asn` | "Routes originated by AS X from all peers" |
| `idx_adj_rib_in_nexthop` | B-tree | `nexthop` | Next-hop grouping |
| `idx_adj_rib_in_updated_at` | B-tree DESC | `updated_at` | Recently changed routes, staleness detection |

---

### `route_events`

Route change history. Every BGP add or withdraw generates a row. Partitioned by day on `ingest_time` for efficient retention management and time-range queries.

Stores events from **both** Loc-RIB and Adj-RIB-In. The `peer_address`, `peer_asn`, `peer_bgp_id`, and `is_post_policy` columns identify the source peer for Adj-RIB-In events; these are `NULL` for Loc-RIB events.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `event_id` | `BYTEA` | **PK** | — | 32-byte SHA-256 hash of the event content. Used for deduplication. |
| `ingest_time` | `TIMESTAMPTZ` | **PK** | — | When the ingester wrote this event (`now()` at insert time). Partition key. |
| `router_id` | `TEXT` | no | — | Router that produced this event. |
| `table_name` | `TEXT` | no | — | BMP table name. |
| `afi` | `SMALLINT` | no | — | `4` or `6`. |
| `prefix` | `CIDR` | no | — | Affected prefix. |
| `path_id` | `BIGINT` | yes | `NULL` | Add-Path identifier. `NULL` when not applicable (translates to 0 in API). |
| `action` | `CHAR(1)` | no | — | `'A'` = announce (add/update), `'D'` = withdraw (delete). |
| `nexthop` | `INET` | yes | `NULL` | Next-hop for announces. `NULL` for withdraws. |
| `as_path` | `TEXT` | yes | `NULL` | AS path at the time of the event. `NULL` for withdraws. |
| `origin` | `TEXT` | yes | `NULL` | Origin attribute. `NULL` for withdraws. |
| `localpref` | `INTEGER` | yes | `NULL` | LOCAL_PREF. |
| `med` | `INTEGER` | yes | `NULL` | MED. |
| `origin_asn` | `INTEGER` | yes | `NULL` | Derived from `as_path`, same logic as `current_routes.origin_asn`. |
| `communities_std` | `TEXT[]` | yes | `NULL` | Standard communities at the time of the event. |
| `communities_ext` | `TEXT[]` | yes | `NULL` | Extended communities. |
| `communities_large` | `TEXT[]` | yes | `NULL` | Large communities. |
| `attrs` | `JSONB` | yes | `NULL` | Extra attributes. |
| `bmp_raw` | `BYTEA` | yes | `NULL` | Raw BMP message bytes. May be zstd-compressed (configurable). |
| `peer_address` | `INET` | yes | `NULL` | Peer IP that sent this route. `NULL` for Loc-RIB events. |
| `peer_asn` | `BIGINT` | yes | `NULL` | Peer ASN. `NULL` for Loc-RIB events. |
| `peer_bgp_id` | `TEXT` | yes | `NULL` | Peer BGP identifier. `NULL` for Loc-RIB events. |
| `is_post_policy` | `BOOLEAN` | yes | `NULL` | `false` = pre-policy, `true` = post-policy. `NULL` for Loc-RIB events. |

**Primary key:** `(event_id, ingest_time)`

**Partitioning:** `PARTITION BY RANGE (ingest_time)` — daily partitions named `route_events_YYYYMMDD`. The ingester's partition manager creates today's and tomorrow's partitions automatically.

**Deduplication:** `ON CONFLICT (event_id, ingest_time) DO NOTHING` — the SHA-256 `event_id` prevents duplicate events from being recorded.

**Retention:** Old partitions are dropped after the configured retention period (default: 30 days).

#### Per-Partition Indexes

Each daily partition gets two indexes created automatically by the partition manager:

| Index Pattern | Type | Columns | Use Case |
|---------------|------|---------|----------|
| `idx_route_events_YYYYMMDD_prefix_history` | B-tree | `(router_id, table_name, afi, prefix, ingest_time DESC)` | Prefix history timeline: "show me all changes to 10.100.0.0/24" |
| `idx_route_events_YYYYMMDD_router_churn` | B-tree | `(router_id, table_name, afi, ingest_time DESC)` | Churn analysis: "how many route changes per minute for this router?" |

---

### `rib_sync_status`

BMP session synchronization state per router/table/AFI for **Loc-RIB only**. Tracks whether the ingester has received a complete RIB dump (End-of-RIB marker). Used internally by the ingester for stale-route purging; useful for the API to show sync health.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `router_id` | `TEXT` | **PK** | — | Router identifier. |
| `table_name` | `TEXT` | **PK** | — | BMP table name. |
| `afi` | `SMALLINT` | **PK** | — | `4` or `6`. |
| `last_parsed_msg_time` | `TIMESTAMPTZ` | yes | `NULL` | Last time the state (JSON) pipeline processed a message for this combination. |
| `last_raw_msg_time` | `TIMESTAMPTZ` | yes | `NULL` | Last time the history (raw) pipeline processed a message. |
| `eor_seen` | `BOOLEAN` | no | `false` | Whether End-of-RIB has been received for this session. |
| `eor_time` | `TIMESTAMPTZ` | yes | `NULL` | When EOR was received. `NULL` if not yet seen. |
| `session_start_time` | `TIMESTAMPTZ` | yes | `NULL` | When the current BMP session started. Used for stale-route purge after EOR. |
| `updated_at` | `TIMESTAMPTZ` | no | `now()` | Last update to this row. |

**Primary key:** `(router_id, table_name, afi)`

**Lifecycle:** Rows are created when the ingester first processes a Loc-RIB message for a router/table/AFI combination. On session termination (BMP Peer Down for Loc-RIB), the entire row is deleted along with all routes for that router/table.

---

### `adj_rib_in_sync_status`

BMP session synchronization state per router/peer/AFI for **Adj-RIB-In** sessions. Tracks End-of-RIB status per peer. Analogous to `rib_sync_status` but keyed by peer address instead of table name.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `router_id` | `TEXT` | **PK** | — | Router identifier (the BMP speaker). |
| `peer_address` | `INET` | **PK** | — | IP address of the BGP neighbor. |
| `afi` | `SMALLINT` | **PK** | — | `4` or `6`. |
| `session_start_time` | `TIMESTAMPTZ` | yes | `NULL` | When the current BMP session for this peer started. |
| `eor_seen` | `BOOLEAN` | no | `false` | Whether End-of-RIB has been received from this peer. |
| `eor_time` | `TIMESTAMPTZ` | yes | `NULL` | When EOR was received. `NULL` if not yet seen. |
| `updated_at` | `TIMESTAMPTZ` | no | `now()` | Last update to this row. |

**Primary key:** `(router_id, peer_address, afi)`

**Lifecycle:** Rows are created when the ingester first processes an Adj-RIB-In message for a router/peer/AFI combination. On BMP Peer Down, the row is deleted along with all routes for that `(router_id, peer_address)` pair.

---

## Materialized Views

### `route_summary`

Pre-aggregated Loc-RIB route counts per router/table/AFI. Refreshed periodically by the ingester's partition manager (runs on the maintenance schedule — typically every few minutes via `REFRESH MATERIALIZED VIEW CONCURRENTLY`).

| Column | Type | Description |
|--------|------|-------------|
| `router_id` | `TEXT` | Router identifier. |
| `table_name` | `TEXT` | BMP table name. |
| `afi` | `SMALLINT` | `4` or `6`. |
| `route_count` | `BIGINT` | Total routes (including ECMP paths). |
| `unique_prefixes` | `BIGINT` | Distinct prefixes (ignoring path_id). |
| `unique_nexthops` | `BIGINT` | Distinct next-hop addresses. |
| `last_update` | `TIMESTAMPTZ` | Most recent `updated_at` across all routes. |

**Unique index:** `(router_id, table_name, afi)` — required for `REFRESH CONCURRENTLY`.

**Staleness:** This view is eventually consistent. It reflects the state as of the last refresh, not real-time. For exact counts, query `current_routes` directly.

---

### `adj_rib_in_summary`

Pre-aggregated Adj-RIB-In route counts per router/peer/policy/table/AFI. Refreshed periodically alongside `route_summary`.

| Column | Type | Description |
|--------|------|-------------|
| `router_id` | `TEXT` | Router identifier. |
| `peer_address` | `INET` | BGP neighbor IP. |
| `peer_asn` | `BIGINT` | BGP neighbor ASN. |
| `is_post_policy` | `BOOLEAN` | Pre-policy or post-policy view. |
| `table_name` | `TEXT` | BMP table name. |
| `afi` | `SMALLINT` | `4` or `6`. |
| `route_count` | `BIGINT` | Total routes from this peer. |
| `unique_prefixes` | `BIGINT` | Distinct prefixes. |
| `unique_nexthops` | `BIGINT` | Distinct next-hop addresses. |
| `last_update` | `TIMESTAMPTZ` | Most recent `updated_at`. |

**Unique index:** `(router_id, peer_address, peer_asn, is_post_policy, table_name, afi)` — required for `REFRESH CONCURRENTLY`.

**Staleness:** Same caveats as `route_summary`. For exact counts, query `adj_rib_in` directly.

---

## Views

### `peers_overview`

Consolidated per-peer summary joining `adj_rib_in` with `routers` metadata. Provides pre-policy vs post-policy route counts at a glance.

| Column | Type | Description |
|--------|------|-------------|
| `router_id` | `TEXT` | Router identifier. |
| `router_hostname` | `TEXT` | Router hostname (from `routers` table). |
| `peer_address` | `INET` | BGP neighbor IP. |
| `peer_asn` | `BIGINT` | BGP neighbor ASN. |
| `peer_bgp_id` | `TEXT` | BGP identifier of the peer. |
| `pre_policy_routes` | `BIGINT` | Route count where `is_post_policy = false`. |
| `post_policy_routes` | `BIGINT` | Route count where `is_post_policy = true`. |
| `total_routes` | `BIGINT` | Total routes from this peer (pre + post policy). |
| `unique_prefixes` | `BIGINT` | Distinct prefixes from this peer. |
| `last_update` | `TIMESTAMPTZ` | Most recent `updated_at` across all routes from this peer. |

---

### `routers_overview`

Consolidated router summary joining all data sources. Ensures routers appear in listings even before all BMP message types are processed. Includes both Loc-RIB and Adj-RIB-In aggregate counts.

| Column | Type | Description |
|--------|------|-------------|
| `router_id` | `TEXT` | Router identifier. |
| `router_ip` | `INET` | Router IP address. |
| `hostname` | `TEXT` | Router hostname. |
| `as_number` | `BIGINT` | Router ASN. |
| `description` | `TEXT` | Router description. |
| `display_name` | `TEXT` | Operator-provided display name. |
| `location` | `TEXT` | Operator-provided location. |
| `first_seen` | `TIMESTAMPTZ` | First observation time. |
| `last_seen` | `TIMESTAMPTZ` | Last BMP message time. |
| `route_count` | `BIGINT` | Loc-RIB route count (from `current_routes`). |
| `unique_prefixes` | `BIGINT` | Distinct Loc-RIB prefixes. |
| `adj_rib_in_route_count` | `BIGINT` | Total Adj-RIB-In routes across all peers. |
| `adj_rib_in_peer_count` | `BIGINT` | Number of distinct BGP peers with Adj-RIB-In data. |
| `all_afis_synced` | `BOOLEAN` | `true` when EOR received for all AFIs (Loc-RIB only). `NULL` if no sync data. |
| `session_start_time` | `TIMESTAMPTZ` | Most recent BMP session start. |
| `sync_updated_at` | `TIMESTAMPTZ` | Last sync status update. |

**Router discovery:** The `known_routers` CTE unions router IDs from `routers`, `rib_sync_status`, `current_routes`, and `adj_rib_in` so a router appears even if only one data source has seen it.

---

## Query Patterns

### Current Loc-RIB

```sql
-- All routes for a router
SELECT * FROM current_routes
WHERE router_id = '10.0.0.2'
ORDER BY prefix;

-- Exact prefix lookup
SELECT * FROM current_routes
WHERE prefix = '10.100.0.0/24';

-- Longest prefix match (which route covers this IP?)
SELECT * FROM current_routes
WHERE prefix >>= '10.100.5.1/32'
ORDER BY masklen(prefix) DESC
LIMIT 1;

-- Routes by origin AS
SELECT prefix, nexthop, as_path FROM current_routes
WHERE origin_asn = 65001;

-- Routes with a specific community
SELECT prefix, nexthop, as_path FROM current_routes
WHERE communities_std @> ARRAY['65001:100'];

-- Routes by next-hop
SELECT prefix, as_path FROM current_routes
WHERE nexthop = '172.30.0.30';

-- Recently changed routes (polling)
SELECT * FROM current_routes
WHERE updated_at > '2026-02-21T20:00:00Z'
ORDER BY updated_at DESC;

-- Cross-router comparison: which routers have this prefix?
SELECT router_id, nexthop, as_path FROM current_routes
WHERE prefix = '10.100.0.0/24'
ORDER BY router_id;
```

### Adj-RIB-In

```sql
-- All peers advertising a specific prefix on a router
SELECT peer_address, peer_asn, peer_bgp_id, is_post_policy,
       nexthop, as_path, origin, localpref, med, origin_asn,
       communities_std, path_id, updated_at
FROM adj_rib_in
WHERE router_id = '10.0.0.2'
  AND prefix = '10.100.0.0/24'
ORDER BY peer_address, is_post_policy;

-- All routes from a specific peer
SELECT afi, prefix, path_id, is_post_policy,
       nexthop, as_path, origin, localpref, med, origin_asn,
       communities_std, updated_at
FROM adj_rib_in
WHERE router_id = '10.0.0.2'
  AND peer_address = '172.30.0.30'
ORDER BY afi, prefix;

-- All Adj-RIB-In routes for a router (paginated)
SELECT peer_address, peer_asn, afi, prefix, path_id,
       is_post_policy, nexthop, as_path, origin, origin_asn, updated_at
FROM adj_rib_in
WHERE router_id = '10.0.0.2'
ORDER BY peer_address, afi, prefix
LIMIT 100 OFFSET 0;

-- Pre-policy only (before import filters)
SELECT * FROM adj_rib_in
WHERE router_id = '10.0.0.2'
  AND is_post_policy = false
ORDER BY peer_address, prefix;

-- Route count per peer (live)
SELECT peer_address, peer_asn, is_post_policy, afi,
       COUNT(*) AS route_count,
       COUNT(DISTINCT prefix) AS unique_prefixes,
       MAX(updated_at) AS last_update
FROM adj_rib_in
WHERE router_id = '10.0.0.2'
GROUP BY peer_address, peer_asn, is_post_policy, afi
ORDER BY peer_address, afi;

-- Route count per peer (from materialized view, fast)
SELECT * FROM adj_rib_in_summary
WHERE router_id = '10.0.0.2';
```

### Cross-Reference: Adj-RIB-In vs Loc-RIB

```sql
-- Compare what each peer offered vs the best path the router selected
SELECT
    'adj_rib_in' AS source,
    a.peer_address::TEXT AS peer_or_table,
    a.peer_asn,
    a.is_post_policy,
    a.nexthop, a.as_path, a.origin, a.localpref, a.med,
    a.origin_asn, a.communities_std, a.path_id, a.updated_at
FROM adj_rib_in a
WHERE a.router_id = '10.0.0.2'
  AND a.prefix = '10.100.0.0/24'
  AND a.afi = 4

UNION ALL

SELECT
    'loc_rib' AS source,
    c.table_name AS peer_or_table,
    NULL::BIGINT AS peer_asn,
    NULL::BOOLEAN AS is_post_policy,
    c.nexthop, c.as_path, c.origin, c.localpref, c.med,
    c.origin_asn, c.communities_std, c.path_id, c.updated_at
FROM current_routes c
WHERE c.router_id = '10.0.0.2'
  AND c.prefix = '10.100.0.0/24'
  AND c.afi = 4

ORDER BY source, peer_or_table;
```

### Peers

```sql
-- All peers for a router with route counts
SELECT * FROM peers_overview
WHERE router_id = '10.0.0.2'
ORDER BY peer_address;

-- Peer sync status (EOR received?)
SELECT * FROM adj_rib_in_sync_status
WHERE router_id = '10.0.0.2'
ORDER BY peer_address, afi;
```

### Route History

```sql
-- History for a specific prefix (Loc-RIB events)
SELECT ingest_time, action, nexthop, as_path, origin_asn
FROM route_events
WHERE router_id = '10.0.0.2'
  AND prefix = '10.100.0.0/24'
  AND peer_address IS NULL
ORDER BY ingest_time DESC
LIMIT 100;

-- History for a specific prefix from a specific peer (Adj-RIB-In events)
SELECT ingest_time, action, peer_address, peer_asn,
       is_post_policy, nexthop, as_path, origin_asn
FROM route_events
WHERE router_id = '10.0.0.2'
  AND prefix = '10.100.0.0/24'
  AND peer_address = '172.30.0.30'
ORDER BY ingest_time DESC
LIMIT 100;

-- Churn rate (events per minute for a router)
SELECT date_trunc('minute', ingest_time) AS minute,
       COUNT(*) AS events,
       COUNT(*) FILTER (WHERE action = 'A') AS adds,
       COUNT(*) FILTER (WHERE action = 'D') AS withdraws
FROM route_events
WHERE router_id = '10.0.0.2'
  AND ingest_time > now() - interval '1 hour'
GROUP BY 1
ORDER BY 1 DESC;

-- All changes in a time window
SELECT ingest_time, prefix, action, nexthop
FROM route_events
WHERE router_id = '10.0.0.2'
  AND ingest_time BETWEEN '2026-02-21 20:00:00+00' AND '2026-02-21 21:00:00+00'
ORDER BY ingest_time DESC;
```

### Sync Health

```sql
-- Loc-RIB sync status: which routers are synced (EOR received)?
SELECT r.router_id, r.hostname, s.afi, s.eor_seen, s.eor_time,
       s.session_start_time, s.updated_at
FROM rib_sync_status s
LEFT JOIN routers r ON r.router_id = s.router_id
ORDER BY s.router_id, s.afi;

-- Adj-RIB-In sync status: which peers have sent EOR?
SELECT r.router_id, r.hostname, a.peer_address, a.afi,
       a.eor_seen, a.eor_time, a.session_start_time, a.updated_at
FROM adj_rib_in_sync_status a
LEFT JOIN routers r ON r.router_id = a.router_id
ORDER BY a.router_id, a.peer_address, a.afi;

-- Routers with stale Loc-RIB data (no messages in 5 minutes)
SELECT router_id, table_name, afi, updated_at
FROM rib_sync_status
WHERE updated_at < now() - interval '5 minutes';
```

### Summary / Dashboard

```sql
-- Router overview with Loc-RIB and Adj-RIB-In counts
SELECT * FROM routers_overview
ORDER BY router_id;

-- Loc-RIB route counts per router (from materialized view, fast)
SELECT * FROM route_summary
ORDER BY router_id, afi;

-- Adj-RIB-In route counts per peer (from materialized view, fast)
SELECT * FROM adj_rib_in_summary
ORDER BY router_id, peer_address, afi;

-- Real-time Loc-RIB counts (slower, always current)
SELECT router_id, table_name, afi,
       COUNT(*) AS route_count,
       COUNT(DISTINCT prefix) AS unique_prefixes
FROM current_routes
GROUP BY router_id, table_name, afi;
```

---

## Data Lifecycle

```
BMP Peer Up (Loc-RIB, peer type 3)
  └─ Ingester processes Sent OPEN message
       └─ UPSERT into `routers` (BGP ID, ASN, operator metadata)
       └─ INSERT/UPDATE `rib_sync_status` (session_start_time = now, eor_seen = false)

BMP Peer Up (Adj-RIB-In, peer type 0/1/2)
  └─ Ingester processes Sent OPEN message
       └─ UPSERT into `routers` (BGP ID, ASN from local speaker)
       └─ INSERT/UPDATE `adj_rib_in_sync_status`

Route Monitoring — Loc-RIB (peer type 3)
  └─ For each prefix in the BGP UPDATE:
       ├─ action='A' → UPSERT into `current_routes`, INSERT into `route_events`
       └─ action='D' → DELETE from `current_routes`, INSERT into `route_events`
  └─ UPDATE `rib_sync_status` (last_parsed_msg_time / last_raw_msg_time)

Route Monitoring — Adj-RIB-In (peer type 0/1/2)
  └─ For each prefix in the BGP UPDATE:
       ├─ action='A' → UPSERT into `adj_rib_in`, INSERT into `route_events` (with peer columns)
       └─ action='D' → DELETE from `adj_rib_in`, INSERT into `route_events` (with peer columns)

End-of-RIB (EOR) — Loc-RIB
  └─ UPDATE `rib_sync_status` (eor_seen = true, eor_time = now)
  └─ DELETE stale routes from `current_routes` WHERE updated_at < session_start_time

End-of-RIB (EOR) — Adj-RIB-In
  └─ UPDATE `adj_rib_in_sync_status` (eor_seen = true, eor_time = now)
  └─ DELETE stale routes from `adj_rib_in` WHERE updated_at < session_start_time
     (scoped to that router/peer)

BMP Peer Down — Loc-RIB (peer type 3)
  └─ DELETE all rows from `current_routes` for that router/table
  └─ DELETE `rib_sync_status` row for that router/table

BMP Peer Down — Adj-RIB-In (peer type 0/1/2)
  └─ DELETE all rows from `adj_rib_in` for that (router_id, peer_address)
  └─ DELETE `adj_rib_in_sync_status` row for that (router_id, peer_address)

Maintenance (periodic)
  └─ Create daily partitions for route_events (today + tomorrow)
  └─ Drop partitions older than retention period (default: 30 days)
  └─ REFRESH MATERIALIZED VIEW CONCURRENTLY route_summary
  └─ REFRESH MATERIALIZED VIEW CONCURRENTLY adj_rib_in_summary
```

---

## Notes for API Developers

1. **Read-only access.** The API should only SELECT from these tables. The ingester is the sole writer — concurrent writes from the API would conflict with the ingester's transactional batches.

2. **`table_name` is often `"UNKNOWN"`.** Not all routers/BMP implementations send the Table Name TLV (type 0). Treat `"UNKNOWN"` as the default RIB.

3. **`path_id` and ECMP.** When Add-Path is in use, multiple routes for the same prefix can exist with different `path_id` values. The composite PK ensures uniqueness. When Add-Path is not in use, `path_id = 0` for all routes.

4. **Community array format.** Standard communities are `"ASN:value"` strings. Extended communities are decoded: `"RT:ASN:value"` for Route Targets, `"SOO:ASN:value"` for Route Origin. Unknown types fall back to hex. Use `@>` (contains) for GIN-indexed lookups.

5. **`origin_asn` is derived.** It's the last ASN in the space-delimited `as_path` string. `NULL` when the path is empty or ends with an AS_SET. Useful for "originated by" queries without parsing `as_path` in the API.

6. **`attrs` JSONB.** Contains any BGP path attributes not mapped to dedicated columns (rare in practice). The API can expose this as an opaque JSON object.

7. **`bmp_raw` in `route_events`.** May be zstd-compressed depending on ingester config (`ingest.store_raw_bytes_compress`). If the API needs to serve raw BMP bytes, it must detect and decompress. The first 4 bytes of zstd-compressed data start with the magic number `0x28B52FFD`.

8. **Partition-aware queries on `route_events`.** Always include `ingest_time` in WHERE clauses to enable partition pruning. Without it, PostgreSQL scans all partitions.

9. **`route_summary` / `adj_rib_in_summary` staleness.** Materialized views are refreshed on the maintenance schedule (every few minutes). For dashboards where a few minutes of lag is acceptable, query the views. For exact counts, query `current_routes` or `adj_rib_in` with `COUNT(*)`.

10. **Session termination deletes routes.** When a BMP session drops, all `current_routes` for that router are removed, and all `adj_rib_in` for that router are removed. The API should handle the case where a previously known router has zero routes (session is down). Check `rib_sync_status` — if no row exists, the Loc-RIB session has terminated. Check `adj_rib_in_sync_status` for per-peer session status.

11. **Loc-RIB vs Adj-RIB-In in `route_events`.** Use `peer_address IS NULL` to filter Loc-RIB-only events. Use `peer_address IS NOT NULL` for Adj-RIB-In events. The `is_post_policy` column distinguishes pre-policy (peer type 0) from post-policy (peer type 1) Adj-RIB-In events.

12. **`peers_overview` for peer dashboards.** Use this view to show all BGP neighbors for a router with pre-policy vs post-policy route counts. Joins with `routers` to include the router hostname.

13. **`routers_overview` for router dashboards.** Includes `adj_rib_in_route_count` and `adj_rib_in_peer_count` alongside Loc-RIB metrics for a complete picture per router.

14. **Pre-policy vs post-policy.** `is_post_policy = false` shows routes **before** the router's import policy is applied. `is_post_policy = true` shows routes **after** import policy. Not all routers send both — the availability depends on the BMP configuration on the router.
