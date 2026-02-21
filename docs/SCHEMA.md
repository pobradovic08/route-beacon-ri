# PostgreSQL Schema Reference

Database used by the `rib-ingester` service. The API layer reads from these tables — the ingester is the sole writer.

**PostgreSQL version:** 16
**Required extension:** `btree_gist` (for GiST indexing on `inet`/`cidr` types)
**Migration:** `migrations/0001_init.sql`

---

## Tables

### `routers`

Router metadata populated from BMP Initiation messages (RFC 7854 §4.3). One row per monitored router. Updated each time the ingester receives a new BMP session initiation.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `router_id` | `TEXT` | **PK** | — | Router identifier. Typically the BGP Router ID (e.g. `10.0.0.2`). |
| `router_ip` | `INET` | yes | `NULL` | IP address the router connected from. |
| `hostname` | `TEXT` | yes | `NULL` | From BMP Initiation TLV type 2 (`sysName`). |
| `as_number` | `BIGINT` | yes | `NULL` | Router's autonomous system number. |
| `description` | `TEXT` | yes | `NULL` | From BMP Initiation TLV type 1 (`sysDescr`). |
| `first_seen` | `TIMESTAMPTZ` | no | `now()` | When this router was first observed. Never overwritten on update. |
| `last_seen` | `TIMESTAMPTZ` | no | `now()` | Last BMP Initiation received. Updated on every new session. |

**Upsert behavior:** `ON CONFLICT (router_id)` updates `router_ip`, `hostname`, `description` (using `COALESCE` to preserve non-null values) and sets `last_seen = now()`. `first_seen` is never overwritten.

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

### `route_events`

Route change history. Every BGP add or withdraw generates a row. Partitioned by day on `ingest_time` for efficient retention management and time-range queries.

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

BMP session synchronization state per router/table/AFI. Tracks whether the ingester has received a complete RIB dump (End-of-RIB marker). Used internally by the ingester for stale-route purging; useful for the API to show sync health.

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

**Lifecycle:** Rows are created when the ingester first processes a message for a router/table/AFI combination. On session termination (BMP Peer Down for Loc-RIB), the entire row is deleted along with all routes for that router/table.

---

## Materialized View

### `route_summary`

Pre-aggregated route counts per router/table/AFI. Refreshed periodically by the ingester's partition manager (runs on the maintenance schedule — typically every few minutes via `REFRESH MATERIALIZED VIEW CONCURRENTLY`).

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

## Query Patterns

### Current RIB

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

### Route History

```sql
-- History for a specific prefix
SELECT ingest_time, action, nexthop, as_path, origin_asn
FROM route_events
WHERE router_id = '10.0.0.2'
  AND prefix = '10.100.0.0/24'
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
-- Which routers are synced (EOR received)?
SELECT r.router_id, r.hostname, s.afi, s.eor_seen, s.eor_time,
       s.session_start_time, s.updated_at
FROM rib_sync_status s
LEFT JOIN routers r ON r.router_id = s.router_id
ORDER BY s.router_id, s.afi;

-- Routers with stale data (no messages in 5 minutes)
SELECT router_id, table_name, afi, updated_at
FROM rib_sync_status
WHERE updated_at < now() - interval '5 minutes';
```

### Summary / Dashboard

```sql
-- Route counts per router (from materialized view, fast)
SELECT * FROM route_summary
ORDER BY router_id, afi;

-- Real-time counts (slower, always current)
SELECT router_id, table_name, afi,
       COUNT(*) AS route_count,
       COUNT(DISTINCT prefix) AS unique_prefixes
FROM current_routes
GROUP BY router_id, table_name, afi;
```

---

## Data Lifecycle

```
BMP Session Start
  └─ Ingester receives Initiation message
       └─ UPSERT into `routers`
       └─ INSERT/UPDATE `rib_sync_status` (session_start_time = now, eor_seen = false)

Route Monitoring (BGP UPDATE with prefixes)
  └─ For each prefix in the UPDATE:
       ├─ action='A' → UPSERT into `current_routes`, INSERT into `route_events`
       └─ action='D' → DELETE from `current_routes`, INSERT into `route_events`
  └─ UPDATE `rib_sync_status` (last_parsed_msg_time / last_raw_msg_time)

End-of-RIB (EOR)
  └─ UPDATE `rib_sync_status` (eor_seen = true, eor_time = now)
  └─ DELETE stale routes from `current_routes` WHERE updated_at < session_start_time

BMP Peer Down (Session Termination)
  └─ DELETE all rows from `current_routes` for that router/table
  └─ DELETE `rib_sync_status` row for that router/table

Maintenance (periodic)
  └─ Create daily partitions for route_events (today + tomorrow)
  └─ Drop partitions older than retention period (default: 30 days)
  └─ REFRESH MATERIALIZED VIEW CONCURRENTLY route_summary
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

9. **`route_summary` staleness.** The materialized view is refreshed on the maintenance schedule (every few minutes). For dashboards where a few minutes of lag is acceptable, query `route_summary`. For exact counts, query `current_routes` with `COUNT(*)`.

10. **Session termination deletes routes.** When a BMP session drops, all `current_routes` for that router are removed. The API should handle the case where a previously known router has zero routes (session is down). Check `rib_sync_status` — if no row exists, the session has terminated.
