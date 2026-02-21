package history

import (
	"context"
	"fmt"
	"time"

	"github.com/route-beacon/rib-ingester/internal/bgp"
	"github.com/route-beacon/rib-ingester/internal/bmp"
	"github.com/route-beacon/rib-ingester/internal/metrics"
	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
)

type Pipeline struct {
	writer          *Writer
	batchSize       int
	flushInterval   time.Duration
	maxPayloadBytes int
	logger          *zap.Logger
}

func NewPipeline(writer *Writer, batchSize, flushIntervalMs, maxPayloadBytes int, logger *zap.Logger) *Pipeline {
	return &Pipeline{
		writer:          writer,
		batchSize:       batchSize,
		flushInterval:   time.Duration(flushIntervalMs) * time.Millisecond,
		maxPayloadBytes: maxPayloadBytes,
		logger:          logger,
	}
}

// Run processes records from the channel until context is cancelled.
func (p *Pipeline) Run(ctx context.Context, records <-chan []*kgo.Record, flushed chan<- []*kgo.Record) {
	var batch []*HistoryRow
	var batchRecords []*kgo.Record
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batchRecords) > 0 {
				p.flush(ctx, batch, batchRecords, flushed)
			}
			return

		case recs, ok := <-records:
			if !ok {
				if len(batchRecords) > 0 {
					p.flush(ctx, batch, batchRecords, flushed)
				}
				return
			}

			for _, rec := range recs {
				rows := p.processRecord(rec)
				if len(rows) > 0 {
					batch = append(batch, rows...)
				}
				batchRecords = append(batchRecords, rec)
			}

			if len(batchRecords) >= p.batchSize {
				if p.flush(ctx, batch, batchRecords, flushed) {
					batch = nil
					batchRecords = nil
				}
			}

			// Cap memory: if repeated flush failures cause the batch to
			// grow beyond 10x the configured size, drop it to prevent
			// unbounded memory growth during prolonged DB outages.
			if len(batchRecords) >= p.batchSize*10 {
				p.logger.Error("dropping oversized batch after repeated flush failures",
					zap.Int("dropped_records", len(batchRecords)),
					zap.Int("dropped_rows", len(batch)),
				)
				batch = nil
				batchRecords = nil
			}

		case <-ticker.C:
			if len(batchRecords) > 0 {
				if p.flush(ctx, batch, batchRecords, flushed) {
					batch = nil
					batchRecords = nil
				}
			}
		}
	}
}

func (p *Pipeline) processRecord(rec *kgo.Record) []*HistoryRow {
	// Step 1: Decode OpenBMP frame.
	bmpBytes, err := DecodeOpenBMPFrame(rec.Value, p.maxPayloadBytes)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("openbmp", "decode").Inc()
		p.logger.Warn("failed to decode OpenBMP frame",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil
	}

	// Step 2: Compute event_id (SHA256 of BMP bytes, NOT OpenBMP wrapper).
	eventID := ComputeEventID(bmpBytes)

	// Step 3: Parse BMP message.
	parsed, err := bmp.Parse(bmpBytes)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("bmp", "parse").Inc()
		p.logger.Warn("failed to parse BMP message",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil
	}

	// Filter: only process Loc-RIB Route Monitoring messages.
	if !parsed.IsLocRIB {
		return nil
	}
	if parsed.MsgType != bmp.MsgTypeRouteMonitoring {
		return nil
	}
	if parsed.BGPData == nil {
		return nil
	}

	// Step 4: Parse BGP UPDATE.
	events, err := bgp.ParseUpdate(parsed.BGPData, parsed.HasAddPath)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("bgp", "parse").Inc()
		p.logger.Warn("failed to parse BGP UPDATE",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil
	}

	if len(events) == 0 {
		return nil
	}

	// Build history rows.
	var rows []*HistoryRow
	for _, ev := range events {
		afiStr := fmt.Sprintf("%d", ev.AFI)
		metrics.KafkaMessagesTotal.WithLabelValues("history", rec.Topic, afiStr, ev.Action).Inc()

		rows = append(rows, &HistoryRow{
			EventID:   eventID,
			RouterID:  bmp.RouterIDFromPeerHeader(bmpBytes[bmp.CommonHeaderSize:]),
			TableName: parsed.TableName,
			Event:     ev,
			BMPRaw:    bmpBytes,
			Topic:     rec.Topic,
		})
	}

	return rows
}

func (p *Pipeline) flush(ctx context.Context, batch []*HistoryRow, records []*kgo.Record, flushed chan<- []*kgo.Record) bool {
	inserted, err := p.writer.FlushBatch(ctx, batch)
	if err != nil {
		p.logger.Error("history batch flush failed", zap.Error(err))
		return false
	}

	p.logger.Debug("history batch flushed",
		zap.Int("batch_size", len(batch)),
		zap.Int64("inserted", inserted),
		zap.Int64("deduped", int64(len(batch))-inserted),
	)

	// Update rib_sync_status.last_raw_msg_time for each router/table/afi seen.
	p.updateSyncStatus(ctx, batch)

	// Signal successful flush for offset commit.
	select {
	case flushed <- records:
	case <-ctx.Done():
	}

	return true
}

// updateSyncStatus updates last_raw_msg_time for each unique router/table/afi in the batch.
func (p *Pipeline) updateSyncStatus(ctx context.Context, batch []*HistoryRow) {
	type key struct{ r, t string; a int }
	seen := make(map[key]bool)

	for _, row := range batch {
		k := key{row.RouterID, row.TableName, row.Event.AFI}
		if seen[k] {
			continue
		}
		seen[k] = true

		_, err := p.writer.pool.Exec(ctx, `
			INSERT INTO rib_sync_status (router_id, table_name, afi, last_raw_msg_time, updated_at)
			VALUES ($1, $2, $3, now(), now())
			ON CONFLICT (router_id, table_name, afi)
			DO UPDATE SET last_raw_msg_time = now(), updated_at = now()`,
			row.RouterID, row.TableName, row.Event.AFI,
		)
		if err != nil {
			p.logger.Warn("failed to update sync status for raw msg",
				zap.String("router_id", row.RouterID),
				zap.Error(err),
			)
		}

		afiStr := fmt.Sprintf("%d", row.Event.AFI)
		metrics.LastMsgTimestamp.WithLabelValues("history", row.RouterID, row.TableName, afiStr).SetToCurrentTime()
	}
}
