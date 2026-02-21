package state

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/route-beacon/rib-ingester/internal/metrics"
	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
)

type Pipeline struct {
	writer         *Writer
	batchSize      int
	flushInterval  time.Duration
	logger         *zap.Logger
}

func NewPipeline(writer *Writer, batchSize int, flushIntervalMs int, logger *zap.Logger) *Pipeline {
	return &Pipeline{
		writer:        writer,
		batchSize:     batchSize,
		flushInterval: time.Duration(flushIntervalMs) * time.Millisecond,
		logger:        logger,
	}
}

// Run processes records from the channel until context is cancelled.
// It returns the records that were successfully flushed for offset commit.
func (p *Pipeline) Run(ctx context.Context, records <-chan []*kgo.Record, flushed chan<- []*kgo.Record) {
	var batch []*ParsedRoute
	var batchRecords []*kgo.Record
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Drain remaining.
			if len(batchRecords) > 0 {
				if err := p.flush(ctx, batch, batchRecords, flushed); err != nil {
					p.logger.Error("final flush failed", zap.Error(err))
				}
			}
			return

		case recs, ok := <-records:
			if !ok {
				if len(batchRecords) > 0 {
					if err := p.flush(ctx, batch, batchRecords, flushed); err != nil {
						p.logger.Error("final flush failed", zap.Error(err))
					}
				}
				return
			}

			for _, rec := range recs {
				parsed, action := p.processRecord(ctx, rec)

				// Always track the record for offset commit, even if parsing
				// failed or the message was filtered. This prevents unparseable
				// records from stalling partition progress.
				batchRecords = append(batchRecords, rec)

				if parsed == nil {
					continue
				}

				switch action {
				case actionRoute:
					batch = append(batch, parsed)
				case actionEOR:
					// Flush any pending batch first.
					if len(batchRecords) > 0 {
						if err := p.flush(ctx, batch, batchRecords, flushed); err != nil {
							p.logger.Error("pre-eor flush failed", zap.Error(err))
						} else {
							batch = nil
							batchRecords = nil
						}
					}
					if err := p.writer.HandleEOR(ctx, parsed.RouterID, parsed.TableName, parsed.AFI); err != nil {
						p.logger.Error("EOR handling failed", zap.Error(err))
					}
				case actionPeerDown:
					// Flush any pending batch first.
					if len(batchRecords) > 0 {
						if err := p.flush(ctx, batch, batchRecords, flushed); err != nil {
							p.logger.Error("pre-peerdown flush failed", zap.Error(err))
						} else {
							batch = nil
							batchRecords = nil
						}
					}
					if err := p.writer.HandleSessionTermination(ctx, parsed.RouterID); err != nil {
						p.logger.Error("session termination failed", zap.Error(err))
					}
				}
			}

			if len(batchRecords) >= p.batchSize {
				if err := p.flush(ctx, batch, batchRecords, flushed); err != nil {
					p.logger.Error("batch flush failed", zap.Error(err))
				} else {
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
					zap.Int("dropped_routes", len(batch)),
				)
				batch = nil
				batchRecords = nil
			}

		case <-ticker.C:
			if len(batchRecords) > 0 {
				if err := p.flush(ctx, batch, batchRecords, flushed); err != nil {
					p.logger.Error("timer flush failed", zap.Error(err))
				} else {
					batch = nil
					batchRecords = nil
				}
			}
		}
	}
}

type recordAction int

const (
	actionRoute    recordAction = iota
	actionEOR
	actionPeerDown
)

func (p *Pipeline) processRecord(ctx context.Context, rec *kgo.Record) (*ParsedRoute, recordAction) {
	topic := rec.Topic

	// Determine if this is a peer topic.
	if strings.Contains(topic, ".parsed.peer") {
		return p.processPeerRecord(ctx, rec)
	}

	// Determine AFI from topic.
	afi := 4
	if strings.Contains(topic, "_v6") {
		afi = 6
	}

	parsed, err := DecodeUnicastPrefix(rec.Value, afi)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("json", "decode").Inc()
		p.logger.Warn("failed to decode unicast prefix message",
			zap.String("topic", topic),
			zap.Error(err),
		)
		return nil, actionRoute
	}

	// Filter: only process Loc-RIB messages.
	if !parsed.IsLocRIB {
		return nil, actionRoute
	}

	afiStr := fmt.Sprintf("%d", parsed.AFI)
	metrics.KafkaMessagesTotal.WithLabelValues("state", topic, afiStr, parsed.Action).Inc()
	metrics.LastMsgTimestamp.WithLabelValues("state", parsed.RouterID, parsed.TableName, afiStr).SetToCurrentTime()

	if parsed.IsEOR {
		return parsed, actionEOR
	}

	return parsed, actionRoute
}

func (p *Pipeline) processPeerRecord(ctx context.Context, rec *kgo.Record) (*ParsedRoute, recordAction) {
	pe, err := DecodePeerMessage(rec.Value)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("json", "peer_decode").Inc()
		p.logger.Warn("failed to decode peer message",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil, actionRoute
	}

	if pe.Action == "peer_down" && pe.IsLocRIB {
		metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "peer_down").Inc()
		return &ParsedRoute{RouterID: pe.RouterID}, actionPeerDown
	}

	return nil, actionRoute
}

func (p *Pipeline) flush(ctx context.Context, batch []*ParsedRoute, records []*kgo.Record, flushed chan<- []*kgo.Record) error {
	if err := p.writer.FlushBatch(ctx, batch); err != nil {
		return err
	}

	// Signal successful flush for offset commit.
	select {
	case flushed <- records:
	case <-ctx.Done():
	}

	return nil
}
