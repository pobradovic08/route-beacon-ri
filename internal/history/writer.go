package history

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"
	"github.com/route-beacon/rib-ingester/internal/bgp"
	"github.com/route-beacon/rib-ingester/internal/metrics"
	"go.uber.org/zap"
)

var zstdEncoder *zstd.Encoder

func init() {
	var err error
	zstdEncoder, err = zstd.NewWriter(nil)
	if err != nil {
		panic(fmt.Sprintf("history: zstd encoder init: %v", err))
	}
}

type Writer struct {
	pool           *pgxpool.Pool
	logger         *zap.Logger
	storeRawBytes  bool
	compressRaw    bool
}

func NewWriter(pool *pgxpool.Pool, logger *zap.Logger, storeRawBytes, compressRaw bool) *Writer {
	return &Writer{
		pool:          pool,
		logger:        logger,
		storeRawBytes: storeRawBytes,
		compressRaw:   compressRaw,
	}
}

// HistoryRow represents a single row to insert into route_events.
type HistoryRow struct {
	EventID   []byte // 32-byte SHA256
	RouterID  string
	TableName string
	Event     *bgp.RouteEvent
	BMPRaw    []byte // Optional raw BMP bytes
	Topic     string // For dedup metric labeling
}

// FlushBatch inserts a batch of history rows into route_events.
// Returns the number of rows actually inserted (after dedup).
func (w *Writer) FlushBatch(ctx context.Context, rows []*HistoryRow) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	start := time.Now()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const insertSQL = `
		INSERT INTO route_events (event_id, ingest_time, router_id, table_name, afi,
			prefix, path_id, action, nexthop, as_path, origin, localpref, med,
			communities_std, communities_ext, communities_large, attrs, bmp_raw)
		VALUES ($1, date_trunc('day', now() AT TIME ZONE 'UTC')::timestamptz, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (event_id, ingest_time) DO NOTHING`

	batch := &pgx.Batch{}
	for _, row := range rows {
		var attrsJSON []byte
		if len(row.Event.Attrs) > 0 {
			attrsJSON, _ = json.Marshal(row.Event.Attrs)
		}

		var rawBytes []byte
		if w.storeRawBytes && row.BMPRaw != nil {
			if w.compressRaw {
				rawBytes = zstdEncoder.EncodeAll(row.BMPRaw, nil)
			} else {
				rawBytes = row.BMPRaw
			}
		}

		batch.Queue(insertSQL,
			row.EventID, row.RouterID, row.TableName, row.Event.AFI,
			row.Event.Prefix, nilIfZero(row.Event.PathID), row.Event.Action,
			nilIfEmpty(row.Event.Nexthop), nilIfEmpty(row.Event.ASPath),
			nilIfEmpty(row.Event.Origin), row.Event.LocalPref, row.Event.MED,
			row.Event.CommStd, row.Event.CommExt, row.Event.CommLarge,
			attrsJSON, rawBytes,
		)
	}

	results := tx.SendBatch(ctx, batch)
	var totalInserted int64
	for i, row := range rows {
		tag, err := results.Exec()
		if err != nil {
			results.Close()
			return 0, fmt.Errorf("insert route_event[%d]: %w", i, err)
		}
		affected := tag.RowsAffected()
		totalInserted += affected
		if affected == 0 {
			metrics.HistoryDedupConflictsTotal.WithLabelValues(row.Topic).Inc()
		}
	}
	if err := results.Close(); err != nil {
		return 0, fmt.Errorf("closing batch results: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}

	dur := time.Since(start).Seconds()
	metrics.DBWriteDuration.WithLabelValues("history", "insert").Observe(dur)
	metrics.DBRowsAffectedTotal.WithLabelValues("history", "route_events", "insert").Add(float64(totalInserted))
	metrics.BatchSize.WithLabelValues("history").Observe(float64(len(rows)))

	return totalInserted, nil
}

// UpdateSyncStatus upserts the rib_sync_status row for a given router/table/afi.
func (w *Writer) UpdateSyncStatus(ctx context.Context, routerID, tableName string, afi int) error {
	_, err := w.pool.Exec(ctx, `
		INSERT INTO rib_sync_status (router_id, table_name, afi, last_raw_msg_time, eor_seen, session_start_time, updated_at)
		VALUES ($1, $2, $3, now(), false, now(), now())
		ON CONFLICT (router_id, table_name, afi)
		DO UPDATE SET last_raw_msg_time = now(), updated_at = now()`,
		routerID, tableName, afi,
	)
	return err
}

func nilIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
