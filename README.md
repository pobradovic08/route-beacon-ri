# rib-ingester

A production-grade Go service that ingests BMP Loc-RIB data from two active/active goBMP collectors via Kafka, maintains current routing state in PostgreSQL (with LPM support), and records 30-day prefix history with cross-collector deduplication.

## Prerequisites

- Go 1.25+
- PostgreSQL 15+ (with `btree_gist` extension)
- Kafka cluster with pre-created topics
- Two goBMP collectors publishing to Kafka

## Build

```bash
go build -o rib-ingester ./cmd/rib-ingester
```

## Configure

Copy and edit the example configuration:

```bash
# For local development
cp config.example.yaml config.yaml

# For systemd deployment (matches the path in deploy/systemd/*.service)
sudo mkdir -p /etc/rib-ingester
sudo cp config.example.yaml /etc/rib-ingester/config.yaml
```

Environment variables override YAML values using `RIB_INGESTER_` prefix with `__` as the nesting delimiter:

```bash
export RIB_INGESTER_POSTGRES__DSN="postgres://user:pass@db01:5432/rib?sslmode=disable"
export RIB_INGESTER_KAFKA__BROKERS="kafka01:9092,kafka02:9092"
```

### Systemd Deployment

The provided systemd unit expects a dedicated user and a binary at `/opt/rib-ingester/`:

```bash
# Create system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rib-ingester

# Install binary
sudo mkdir -p /opt/rib-ingester
sudo cp rib-ingester /opt/rib-ingester/rib-ingester

# Install config
sudo mkdir -p /etc/rib-ingester
sudo cp config.example.yaml /etc/rib-ingester/config.yaml
# Edit /etc/rib-ingester/config.yaml with your settings

# Enable and start
sudo cp deploy/systemd/rib-ingester.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rib-ingester
```

## Database Setup

```bash
# Run schema migrations
./rib-ingester migrate --config config.yaml

# Create initial partitions
./rib-ingester maintenance --config config.yaml
```

## Kafka Topics

Create these topics before starting the service:

```bash
# For collector A
kafka-topics.sh --create --topic cola.gobmp.parsed.unicast_prefix_v4 --partitions 4
kafka-topics.sh --create --topic cola.gobmp.parsed.unicast_prefix_v6 --partitions 4
kafka-topics.sh --create --topic cola.gobmp.parsed.peer --partitions 2
kafka-topics.sh --create --topic cola.gobmp.bmp_raw --partitions 4

# For collector B (same with colb prefix)
kafka-topics.sh --create --topic colb.gobmp.parsed.unicast_prefix_v4 --partitions 4
kafka-topics.sh --create --topic colb.gobmp.parsed.unicast_prefix_v6 --partitions 4
kafka-topics.sh --create --topic colb.gobmp.parsed.peer --partitions 2
kafka-topics.sh --create --topic colb.gobmp.bmp_raw --partitions 4
```

## Run

```bash
./rib-ingester serve --config config.yaml
```

## Schema Overview

### current_routes
Current Loc-RIB state per router/table/AFI/prefix/path_id. Supports LPM queries via GiST index with `inet_ops`.

### route_events
Historical route changes (additions/withdrawals) partitioned by day on `ingest_time`. Deduplicated across collectors via SHA256-based `event_id` with `ON CONFLICT DO NOTHING`.

### routers
Router metadata populated from BMP Initiation messages. Stores router IP, hostname (sysName), AS number, and description (sysDescr). Updated on each new BMP session via UPSERT with COALESCE semantics to avoid overwriting existing values with empty fields.

### route_summary (materialized view)
Pre-aggregated route counts per router/table/AFI. Refreshed periodically by the maintenance loop using `REFRESH MATERIALIZED VIEW CONCURRENTLY`.

### routers_overview (view)
Discovers routers from all data sources (`routers`, `rib_sync_status`, `current_routes`) to ensure routers appear in listings even before BMP Initiation is processed. Joins router metadata, route counts, and sync status.

### rib_sync_status
Tracks per-router/table/AFI synchronization state including EOR status, session start time, and last message timestamps.

## Operational Notes

- **Multi-collector dedup**: SHA256 hash computed on BMP message bytes only (NOT the OpenBMP wrapper), ensuring identical messages from both collectors produce the same `event_id`.
- **EOR handling**: After End-of-RIB, routes not re-announced since session start are purged from `current_routes`.
- **Session termination**: When a Loc-RIB peer goes down, all routes and sync status for that router are immediately purged.
- **LPM queries**: Use `prefix >>= $ip ORDER BY masklen(prefix) DESC LIMIT 1` for longest-prefix match.
- **Router metadata**: BMP Initiation messages are parsed for sysName/sysDescr TLVs and upserted into the `routers` table. The router IP is extracted from the OpenBMP v1.7 header.
- **Partition retention**: Run `./rib-ingester maintenance` daily (via systemd timer or cron) to create new partitions and drop those older than the configured retention period.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/healthz` | Liveness probe (always 200) |
| `/readyz` | Readiness probe (200 if DB + Kafka consumers healthy) |
| `/metrics` | Prometheus metrics |

## Known Router Non-Compliance

### Arista cEOS: Add-Path F-bit missing in BMP Loc-RIB (RFC 9069 Section 4.2)

Arista cEOS (tested with cEOS-lab) sends Add-Path encoded NLRI in BMP Loc-RIB Route Monitoring messages but does **not** set the F-bit (0x80) in the per-peer header's peer flags field. Per RFC 9069 Section 4.2, the F-bit "indicates that the Loc-RIB is conveying ADD-PATH information" and MUST be set when Add-Path encoding is used.

**Impact**: Without the F-bit, the BGP UPDATE parser does not read 4-byte path IDs from the NLRI, causing byte misalignment and garbled prefix parsing (e.g. `0.0.0.0/0` or invalid CIDRs like `24.10.0.0/13`).

**Workaround**: `ParseUpdateAutoDetect` in `internal/bgp/update.go` detects this condition by retrying with Add-Path enabled when the initial parse yields suspicious results: either all default-route prefixes (`0.0.0.0/0` or `::/0`) or any invalid CIDRs with host bits set beyond the network mask (e.g. `100.2.0.0/10`). The latter case occurs with ECMP Add-Path data where small path IDs produce garbled but non-default-route prefixes when misinterpreted as prefix lengths. A warning is logged when auto-detection overrides the F-bit.

### Arista cEOS: Peer Address zero in Loc-RIB per-peer header (RFC 9069 Section 4.1)

RFC 9069 Section 4.1 specifies that for Loc-RIB (peer type 3), the Peer Address is set to zero, but the Peer BGP ID field (per-peer header offset 30) contains the local router's BGP identifier. FRRouting non-standardly populates the Peer Address with the router's address, masking this distinction.

The ingester handles both cases: `RouterIDFromPeerHeader` checks the Peer Address first; if it is all zeros, it falls back to the Peer BGP ID field.

### goBMP: Initiation messages dropped from raw topic ([#354](https://github.com/sbezverk/gobmp/issues/354))

When using goBMP with `-bmp-raw=true`, BMP Initiation (type 4) and Termination (type 5) messages are dropped from the `gobmp.raw` Kafka topic because `produceRawMessage()` requires a per-peer header to construct the OpenBMP v1.7 binary header. Initiation and Termination messages have no per-peer header per RFC 7854 §4.3/§4.5.

**Impact**: The `routers` table will not be populated when consuming only the raw topic. Router metadata collection requires either a fix upstream in goBMP or consuming parsed topics alongside raw.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
```
