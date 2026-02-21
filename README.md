# rib-ingester

A production-grade Go service that ingests BMP Loc-RIB data from two active/active goBMP collectors via Kafka, maintains current routing state in PostgreSQL (with LPM support), and records 30-day prefix history with cross-collector deduplication.

## Prerequisites

- Go 1.22+
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

### rib_sync_status
Tracks per-router/table/AFI synchronization state including EOR status, session start time, and last message timestamps.

## Operational Notes

- **Multi-collector dedup**: SHA256 hash computed on BMP message bytes only (NOT the OpenBMP wrapper), ensuring identical messages from both collectors produce the same `event_id`.
- **EOR handling**: After End-of-RIB, routes not re-announced since session start are purged from `current_routes`.
- **Session termination**: When a Loc-RIB peer goes down, all routes and sync status for that router are immediately purged.
- **LPM queries**: Use `prefix >>= $ip ORDER BY masklen(prefix) DESC LIMIT 1` for longest-prefix match.
- **Partition retention**: Run `./rib-ingester maintenance` daily (via systemd timer or cron) to create new partitions and drop those older than the configured retention period.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/healthz` | Liveness probe (always 200) |
| `/readyz` | Readiness probe (200 if DB + Kafka consumers healthy) |
| `/metrics` | Prometheus metrics |

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
```
