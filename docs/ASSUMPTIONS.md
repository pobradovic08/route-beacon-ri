# Engineering Assumptions and Decisions

## Technology Decisions

### TD-001: Kafka Client — franz-go (kgo)
- **Decision**: Use `github.com/twmb/franz-go/pkg/kgo` v1.20.7
- **Rationale**: High performance, pure Go, excellent manual offset commit control. No CGo dependency.
- **Alternatives rejected**: Sarama (heavier API), confluent-kafka-go (CGo dependency)

### TD-002: PostgreSQL Driver — pgx v5
- **Decision**: Use `github.com/jackc/pgx/v5/pgxpool` v5.8.0
- **Rationale**: Native Go driver with connection pooling and CIDR/INET type handling.
- **Alternatives rejected**: lib/pq (maintenance mode), database/sql (loses type support)

### TD-003: BMP/BGP Parsing — Custom parsers
- **Decision**: Implement custom parsers in `internal/bmp` and `internal/bgp`
- **Rationale**: Full control over RFC 9069 Loc-RIB identification (peer_type==3, Table Name TLV). ~500 lines total with comprehensive test coverage.
- **Alternatives rejected**: goBMP packages (peer_type not clearly exposed, upstream dependency risk)

### TD-004: Configuration — koanf v2
- **Decision**: Use `github.com/knadh/koanf/v2` v2.3.2 with YAML + env overlay
- **Rationale**: Clean API, layered configuration, lighter than Viper.

### TD-005: Logging — zap
- **Decision**: Use `go.uber.org/zap` for structured logging.

### TD-006: Metrics — Prometheus client
- **Decision**: Use `github.com/prometheus/client_golang/prometheus`.

### TD-007: Migrations — Built-in runner
- **Decision**: Simple SQL migration runner reading numbered `.sql` files from `migrations/`.
- **Rationale**: Minimal dependencies. Migration logic is straightforward.

## Design Decisions

### DD-001: path_id NULL handling
- **Decision**: `path_id BIGINT NOT NULL DEFAULT 0` in `current_routes`. 0 is the sentinel for "no Add-Path / single path".
- **Rationale**: PostgreSQL does not allow NULL in primary key columns.

### DD-002: route_events PK includes ingest_time
- **Decision**: Primary key is `(event_id, ingest_time)`.
- **Rationale**: PostgreSQL requires the partition key in the PK for range-partitioned tables.
- **Risk**: Same BMP message processed on two different days creates two rows (benign).

### DD-003: EOR Stale Route Purge
- **Decision**: Track `session_start_time` in `rib_sync_status`. After EOR, DELETE from `current_routes` WHERE `updated_at < session_start_time`.
- **Rationale**: Avoids in-memory "seen" prefix sets. Works correctly across restarts.

### DD-004: Session Termination Detection
- **Decision**: Subscribe to goBMP `parsed.peer` topics. On `peer_down` for a Loc-RIB peer, purge all `current_routes` and `rib_sync_status` for that router.

### DD-005: Parse Failure Handling
- **Decision**: If BMP/BGP parsing fails, skip the insert. Do not store partial/broken history rows.
- **Rationale**: The `prefix` field is NOT NULL (CIDR type). Broken rows would confuse queries.

### DD-006: Parsed Pipeline Dedup Strategy
- **Decision**: The state pipeline does NOT need dedup because its operations are idempotent (UPSERT/DELETE).
- **Rationale**: Only the history pipeline needs dedup (creates new rows).
