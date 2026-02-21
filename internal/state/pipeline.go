package state

import (
	"context"
	"fmt"
	"strings"
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
	rawMode         bool
	maxPayloadBytes int
	logger          *zap.Logger
}

func NewPipeline(writer *Writer, batchSize int, flushIntervalMs int, rawMode bool, maxPayloadBytes int, logger *zap.Logger) *Pipeline {
	return &Pipeline{
		writer:          writer,
		batchSize:       batchSize,
		flushInterval:   time.Duration(flushIntervalMs) * time.Millisecond,
		rawMode:         rawMode,
		maxPayloadBytes: maxPayloadBytes,
		logger:          logger,
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
				routes, action := p.processRecord(ctx, rec)

				// Always track the record for offset commit, even if parsing
				// failed or the message was filtered. This prevents unparseable
				// records from stalling partition progress.
				batchRecords = append(batchRecords, rec)

				if len(routes) == 0 {
					continue
				}

				switch action {
				case actionRoute:
					batch = append(batch, routes...)
				case actionEOR:
					// Flush pending routes to DB before EOR handling.
					// If flush fails, keep batch intact for retry and
					// skip HandleEOR to avoid advancing offsets past
					// unflushed routes.
					if len(batch) > 0 {
						if err := p.writer.FlushBatch(ctx, batch); err != nil {
							p.logger.Error("pre-eor flush failed", zap.Error(err))
							continue
						}
						batch = nil
					}
					if err := p.writer.HandleEOR(ctx, routes[0].RouterID, routes[0].TableName, routes[0].AFI); err != nil {
						p.logger.Error("EOR handling failed", zap.Error(err))
					} else if len(batchRecords) > 0 {
						// EOR succeeded — now safe to commit offsets.
						select {
						case flushed <- batchRecords:
						case <-ctx.Done():
						}
						batchRecords = nil
					}
				case actionPeerDown:
					// Flush pending routes to DB before session termination.
					// If flush fails, keep batch for retry and skip termination.
					if len(batch) > 0 {
						if err := p.writer.FlushBatch(ctx, batch); err != nil {
							p.logger.Error("pre-peerdown flush failed", zap.Error(err))
							continue
						}
						batch = nil
					}
					if err := p.writer.HandleSessionTermination(ctx, routes[0].RouterID); err != nil {
						p.logger.Error("session termination failed", zap.Error(err))
					} else if len(batchRecords) > 0 {
						// Session termination succeeded — now safe to commit offsets.
						select {
						case flushed <- batchRecords:
						case <-ctx.Done():
						}
						batchRecords = nil
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
			// grow beyond 10x the configured size, drop the in-memory
			// batch to prevent unbounded memory growth. Offsets are NOT
			// committed so records will be re-consumed on restart.
			if len(batchRecords) >= p.batchSize*10 {
				p.logger.Error("dropping oversized batch after repeated flush failures",
					zap.Int("dropped_records", len(batchRecords)),
					zap.Int("dropped_routes", len(batch)),
				)
				metrics.BatchDroppedTotal.WithLabelValues("state").Inc()
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

func (p *Pipeline) processRecord(ctx context.Context, rec *kgo.Record) ([]*ParsedRoute, recordAction) {
	if p.rawMode {
		return p.processRawRecord(ctx, rec)
	}

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
		return []*ParsedRoute{parsed}, actionEOR
	}

	return []*ParsedRoute{parsed}, actionRoute
}

func (p *Pipeline) processPeerRecord(ctx context.Context, rec *kgo.Record) ([]*ParsedRoute, recordAction) {
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
		return []*ParsedRoute{{RouterID: pe.RouterID}}, actionPeerDown
	}

	return nil, actionRoute
}

func (p *Pipeline) processRawRecord(ctx context.Context, rec *kgo.Record) ([]*ParsedRoute, recordAction) {
	bmpBytes, err := bmp.DecodeOpenBMPFrame(rec.Value, p.maxPayloadBytes)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("raw", "openbmp_decode").Inc()
		p.logger.Warn("failed to decode OpenBMP frame",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil, actionRoute
	}

	parsed, err := bmp.Parse(bmpBytes)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("raw", "bmp_parse").Inc()
		p.logger.Warn("failed to parse BMP message",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil, actionRoute
	}

	if !parsed.IsLocRIB {
		return nil, actionRoute
	}

	if parsed.MsgType == bmp.MsgTypePeerDown {
		routerID := bmp.RouterIDFromPeerHeader(bmpBytes[bmp.CommonHeaderSize:])
		metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "peer_down").Inc()
		return []*ParsedRoute{{RouterID: routerID}}, actionPeerDown
	}

	if parsed.MsgType != bmp.MsgTypeRouteMonitoring || parsed.BGPData == nil {
		return nil, actionRoute
	}

	// Verify this is actually a BGP UPDATE before parsing.
	// ParseUpdate returns (nil, nil) for non-UPDATE types (e.g. KEEPALIVE),
	// which would be misclassified as EOR if we didn't check here.
	if len(parsed.BGPData) < bgp.BGPHeaderSize || parsed.BGPData[18] != bgp.BGPMsgTypeUpdate {
		return nil, actionRoute
	}

	events, err := bgp.ParseUpdate(parsed.BGPData, parsed.HasAddPath)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("raw", "bgp_parse").Inc()
		p.logger.Warn("failed to parse BGP UPDATE",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil, actionRoute
	}

	routerID := bmp.RouterIDFromPeerHeader(bmpBytes[bmp.CommonHeaderSize:])

	// EOR: empty UPDATE means End-of-RIB.
	if len(events) == 0 {
		afi := bgp.DetectEORAFI(parsed.BGPData)
		afiStr := fmt.Sprintf("%d", afi)
		metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, afiStr, "eor").Inc()
		metrics.LastMsgTimestamp.WithLabelValues("state", routerID, parsed.TableName, afiStr).SetToCurrentTime()
		return []*ParsedRoute{{
			RouterID:  routerID,
			TableName: parsed.TableName,
			AFI:       afi,
			IsLocRIB:  true,
			IsEOR:     true,
		}}, actionEOR
	}

	routes := make([]*ParsedRoute, 0, len(events))
	for _, ev := range events {
		afiStr := fmt.Sprintf("%d", ev.AFI)
		metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, afiStr, ev.Action).Inc()
		metrics.LastMsgTimestamp.WithLabelValues("state", routerID, parsed.TableName, afiStr).SetToCurrentTime()

		r := &ParsedRoute{
			RouterID:  routerID,
			TableName: parsed.TableName,
			AFI:       ev.AFI,
			Prefix:    ev.Prefix,
			PathID:    ev.PathID,
			Action:    ev.Action,
			IsLocRIB:  true,
			Nexthop:   ev.Nexthop,
			ASPath:    ev.ASPath,
			Origin:    ev.Origin,
			LocalPref: ev.LocalPref,
			MED:       ev.MED,
			CommStd:   ev.CommStd,
			CommExt:   ev.CommExt,
			CommLarge: ev.CommLarge,
		}
		if len(ev.Attrs) > 0 {
			attrs := make(map[string]any, len(ev.Attrs))
			for k, v := range ev.Attrs {
				attrs[k] = v
			}
			r.Attrs = attrs
		}
		routes = append(routes, r)
	}

	return routes, actionRoute
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
