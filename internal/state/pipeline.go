package state

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/route-beacon/rib-ingester/internal/bgp"
	"github.com/route-beacon/rib-ingester/internal/bmp"
	"github.com/route-beacon/rib-ingester/internal/config"
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
	routerMeta      map[string]config.RouterMeta
}

func NewPipeline(writer *Writer, batchSize int, flushIntervalMs int, rawMode bool, maxPayloadBytes int, logger *zap.Logger, routerMeta map[string]config.RouterMeta) *Pipeline {
	if routerMeta == nil {
		routerMeta = make(map[string]config.RouterMeta)
	}
	return &Pipeline{
		writer:          writer,
		batchSize:       batchSize,
		flushInterval:   time.Duration(flushIntervalMs) * time.Millisecond,
		rawMode:         rawMode,
		maxPayloadBytes: maxPayloadBytes,
		logger:          logger,
		routerMeta:      routerMeta,
	}
}

// Run processes records from the channel until context is cancelled.
// It returns the records that were successfully flushed for offset commit.
func (p *Pipeline) Run(ctx context.Context, records <-chan []*kgo.Record, flushed chan<- []*kgo.Record) {
	var batch []*ParsedRoute
	var adjBatch []*ParsedRoute
	var batchRecords []*kgo.Record
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Drain remaining with a fresh context so writes are not
			// immediately cancelled by the already-done parent context.
			if len(batchRecords) > 0 {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := p.flushAll(shutdownCtx, batch, adjBatch, batchRecords, flushed); err != nil {
					p.logger.Error("final flush failed", zap.Error(err))
				}
			}
			return

		case recs, ok := <-records:
			if !ok {
				if len(batchRecords) > 0 {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := p.flushAll(shutdownCtx, batch, adjBatch, batchRecords, flushed); err != nil {
						p.logger.Error("final flush failed", zap.Error(err))
					}
				}
				return
			}

			for _, rec := range recs {
				routes, action := p.processRecord(ctx, rec)

				if len(routes) == 0 {
					// Always track the record for offset commit, even if
					// parsing failed or the message was filtered. This
					// prevents unparseable records from stalling partition
					// progress.
					batchRecords = append(batchRecords, rec)
					continue
				}

				switch action {
				case actionRoute:
					batchRecords = append(batchRecords, rec)
					batch = append(batch, routes...)
				case actionEOR:
					// A raw record may contain both regular routes and
					// EOR markers. Separate them, flush routes first,
					// then handle each EOR.
					for _, r := range routes {
						if !r.IsEOR {
							batch = append(batch, r)
						}
					}
					if len(batch) > 0 {
						if err := p.writer.FlushBatch(ctx, batch); err != nil {
							p.logger.Error("pre-eor flush failed", zap.Error(err))
							continue
						}
						batch = nil
					}
					eorFailed := false
					for _, r := range routes {
						if !r.IsEOR {
							continue
						}
						if err := p.writer.HandleEOR(ctx, r.RouterID, r.TableName, r.AFI); err != nil {
							p.logger.Error("EOR handling failed", zap.Error(err))
							eorFailed = true
						}
					}
					// Only commit offsets if all EOR handlers succeeded.
					if eorFailed {
						continue
					}
					batchRecords = append(batchRecords, rec)
					if len(batchRecords) > 0 {
						select {
						case flushed <- batchRecords:
						case <-ctx.Done():
						}
						batchRecords = nil
					}
				case actionPeerDown:
					// Flush pending routes to DB before session termination.
					if len(batch) > 0 {
						if err := p.writer.FlushBatch(ctx, batch); err != nil {
							p.logger.Error("pre-peerdown flush failed", zap.Error(err))
							continue
						}
						batch = nil
					}
					if err := p.writer.HandleSessionTermination(ctx, routes[0].RouterID, routes[0].TableName); err != nil {
						p.logger.Error("session termination failed", zap.Error(err))
					} else {
						// Also purge all adj_rib_in for the router since BMP session loss
						// means all peer monitoring data is stale.
						if err := p.writer.HandleAdjRibInSessionTermination(ctx, routes[0].RouterID); err != nil {
							p.logger.Error("adj_rib_in session purge failed", zap.Error(err))
						}
						adjBatch = nil // Clear any pending adj routes for this router.
						batchRecords = append(batchRecords, rec)
						if len(batchRecords) > 0 {
							select {
							case flushed <- batchRecords:
							case <-ctx.Done():
							}
							batchRecords = nil
						}
					}

				case actionAdjRibInRoute:
					batchRecords = append(batchRecords, rec)
					adjBatch = append(adjBatch, routes...)

				case actionAdjRibInEOR:
					// Flush pending adj_rib_in routes, then purge stale.
					if len(adjBatch) > 0 {
						if err := p.writer.FlushAdjRibInBatch(ctx, adjBatch); err != nil {
							p.logger.Error("pre-adj-eor flush failed", zap.Error(err))
							continue
						}
						adjBatch = nil
					}
					eorFailed := false
					for _, r := range routes {
						if !r.IsEOR {
							continue
						}
						if err := p.writer.HandleAdjRibInEOR(ctx, r.RouterID, r.PeerAddress, r.TableName, r.AFI); err != nil {
							p.logger.Error("adj_rib_in EOR handling failed", zap.Error(err))
							eorFailed = true
						}
					}
					if !eorFailed {
						batchRecords = append(batchRecords, rec)
					}

				case actionAdjRibInPeerDown:
					// Flush pending adj_rib_in routes, then delete peer's routes.
					if len(adjBatch) > 0 {
						if err := p.writer.FlushAdjRibInBatch(ctx, adjBatch); err != nil {
							p.logger.Error("pre-adj-peerdown flush failed", zap.Error(err))
							continue
						}
						adjBatch = nil
					}
					if err := p.writer.HandleAdjRibInPeerDown(ctx, routes[0].RouterID, routes[0].PeerAddress); err != nil {
						p.logger.Error("adj_rib_in peer down failed", zap.Error(err))
					} else {
						batchRecords = append(batchRecords, rec)
					}
				}
			}

			if len(batchRecords) >= p.batchSize {
				if err := p.flushAll(ctx, batch, adjBatch, batchRecords, flushed); err != nil {
					p.logger.Error("batch flush failed", zap.Error(err))
				} else {
					batch = nil
					adjBatch = nil
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
					zap.Int("dropped_routes", len(batch)+len(adjBatch)),
				)
				metrics.BatchDroppedTotal.WithLabelValues("state").Inc()
				batch = nil
				adjBatch = nil
				batchRecords = nil
			}

		case <-ticker.C:
			if len(batchRecords) > 0 {
				if err := p.flushAll(ctx, batch, adjBatch, batchRecords, flushed); err != nil {
					p.logger.Error("timer flush failed", zap.Error(err))
				} else {
					batch = nil
					adjBatch = nil
					batchRecords = nil
				}
			}
		}
	}
}

type recordAction int

const (
	actionRoute             recordAction = iota
	actionEOR
	actionPeerDown
	actionAdjRibInRoute     // Adj-RIB-In route add/withdraw
	actionAdjRibInEOR       // Adj-RIB-In End-of-RIB
	actionAdjRibInPeerDown  // Non-Loc-RIB peer down
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

	if !pe.IsLocRIB {
		return nil, actionRoute
	}

	if pe.Action == "peer_up" {
		metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "peer_up").Inc()
		// PeerUp is session-level — reset both AFI 4 and 6.
		for _, afi := range []int{4, 6} {
			if err := p.writer.UpdateSessionStart(ctx, pe.RouterID, pe.TableName, afi); err != nil {
				p.logger.Error("UpdateSessionStart failed",
					zap.String("router_id", pe.RouterID),
					zap.String("table_name", pe.TableName),
					zap.Int("afi", afi),
					zap.Error(err),
				)
			}
		}
		return nil, actionRoute
	}

	if pe.Action == "peer_down" {
		metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "peer_down").Inc()
		return []*ParsedRoute{{RouterID: pe.RouterID, TableName: pe.TableName}}, actionPeerDown
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

	// A single raw Kafka record may contain multiple concatenated BMP
	// messages (goBMP bundles an entire TCP read into one record).
	msgs, err := bmp.ParseAll(bmpBytes)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("raw", "bmp_parse").Inc()
		p.logger.Warn("failed to parse BMP messages",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil, actionRoute
	}

	// Extract router ID from the OpenBMP v1.7 header (fallback for Loc-RIB).
	obmpRouterIP := bmp.RouterIPFromOpenBMPV17(rec.Value)

	var routes []*ParsedRoute
	finalAction := actionRoute

	for _, parsed := range msgs {
		if parsed.IsLocRIB {
			// --- Loc-RIB path (UNCHANGED) ---
			peerHdrOffset := parsed.Offset + bmp.CommonHeaderSize
			routerID := bmp.RouterIDFromPeerHeader(bmpBytes[peerHdrOffset:])
			if routerID == "" || routerID == "::" || routerID == "0.0.0.0" {
				if obmpRouterIP != "" {
					routerID = obmpRouterIP
				}
			}

			if parsed.MsgType == bmp.MsgTypePeerUp {
				metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "peer_up").Inc()
				for _, afi := range []int{4, 6} {
					if err := p.writer.UpdateSessionStart(ctx, routerID, parsed.TableName, afi); err != nil {
						p.logger.Error("UpdateSessionStart failed",
							zap.String("router_id", routerID),
							zap.String("table_name", parsed.TableName),
							zap.Int("afi", afi),
							zap.Error(err),
						)
					}
				}
				continue
			}

			if parsed.MsgType == bmp.MsgTypePeerDown {
				metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "peer_down").Inc()
				p.logger.Info("BMP Peer Down received",
					zap.String("router_id", routerID),
					zap.String("table_name", parsed.TableName),
					zap.Uint8("reason_code", parsed.PeerDownReason),
				)
				finalAction = actionPeerDown
				routes = append(routes, &ParsedRoute{RouterID: routerID, TableName: parsed.TableName})
				break
			}

			if parsed.MsgType != bmp.MsgTypeRouteMonitoring || parsed.BGPData == nil {
				continue
			}

			if len(parsed.BGPData) < bgp.BGPHeaderSize || parsed.BGPData[18] != bgp.BGPMsgTypeUpdate {
				continue
			}

			events, actualAddPath, err := bgp.ParseUpdateAutoDetect(parsed.BGPData, parsed.HasAddPath)
			if err != nil {
				metrics.ParseErrorsTotal.WithLabelValues("raw", "bgp_parse").Inc()
				p.logger.Warn("failed to parse BGP UPDATE",
					zap.String("topic", rec.Topic),
					zap.Error(err),
				)
				continue
			}

			if actualAddPath != parsed.HasAddPath {
				p.logger.Warn("Add-Path auto-detected: router sends Add-Path NLRI without F-bit in BMP per-peer header (RFC 9069 non-compliance)",
					zap.String("router_id", routerID),
					zap.String("table_name", parsed.TableName),
				)
			}

			// EOR: empty UPDATE means End-of-RIB.
			if len(events) == 0 {
				afi := bgp.DetectEORAFI(parsed.BGPData)
				afiStr := fmt.Sprintf("%d", afi)
				metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, afiStr, "eor").Inc()
				metrics.LastMsgTimestamp.WithLabelValues("state", routerID, parsed.TableName, afiStr).SetToCurrentTime()
				routes = append(routes, &ParsedRoute{
					RouterID:  routerID,
					TableName: parsed.TableName,
					AFI:       afi,
					IsLocRIB:  true,
					IsEOR:     true,
				})
				finalAction = actionEOR
				continue
			}

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
					OriginASN: bgp.OriginASN(ev.ASPath),
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
		} else {
			// --- Adj-RIB-In path (peer types 0/1/2) ---
			// For non-Loc-RIB, router ID comes from OBMP header (the BMP speaker),
			// NOT from per-peer header offset 30 (which is the peer's BGP ID).
			routerID := obmpRouterIP

			switch parsed.MsgType {
			case bmp.MsgTypePeerUp:
				// Non-Loc-RIB Peer Up: record session start for stale route tracking.
				metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "adj_peer_up").Inc()
				if p.writer != nil {
					for _, afi := range []int{4, 6} {
						if err := p.writer.UpdateAdjRibInSessionStart(ctx, routerID, parsed.PeerAddress, afi); err != nil {
							p.logger.Error("UpdateAdjRibInSessionStart failed",
								zap.String("router_id", routerID),
								zap.String("peer_address", parsed.PeerAddress),
								zap.Int("afi", afi),
								zap.Error(err),
							)
						}
					}
				}
				continue

			case bmp.MsgTypePeerDown:
				// Non-Loc-RIB Peer Down: delete all adj_rib_in for this peer.
				metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "adj_peer_down").Inc()
				p.logger.Info("Adj-RIB-In Peer Down received",
					zap.String("router_id", routerID),
					zap.String("peer_address", parsed.PeerAddress),
					zap.Uint8("reason_code", parsed.PeerDownReason),
				)
				finalAction = actionAdjRibInPeerDown
				routes = append(routes, &ParsedRoute{
					RouterID:     routerID,
					PeerAddress:  parsed.PeerAddress,
					PeerAS:       parsed.PeerAS,
					PeerBGPID:    parsed.PeerBGPID,
					IsPostPolicy: parsed.IsPostPolicy,
				})
				continue

			case bmp.MsgTypeRouteMonitoring:
				if parsed.BGPData == nil {
					continue
				}
				if len(parsed.BGPData) < bgp.BGPHeaderSize || parsed.BGPData[18] != bgp.BGPMsgTypeUpdate {
					continue
				}

				events, _, err := bgp.ParseUpdateAutoDetect(parsed.BGPData, parsed.HasAddPath)
				if err != nil {
					metrics.ParseErrorsTotal.WithLabelValues("raw", "bgp_parse_adj").Inc()
					continue
				}

				// EOR for Adj-RIB-In
				if len(events) == 0 {
					afi := bgp.DetectEORAFI(parsed.BGPData)
					afiStr := fmt.Sprintf("%d", afi)
					metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, afiStr, "adj_eor").Inc()

					tableName := parsed.TableName
					if tableName == "UNKNOWN" {
						tableName = ""
					}

					routes = append(routes, &ParsedRoute{
						RouterID:     routerID,
						PeerAddress:  parsed.PeerAddress,
						PeerAS:       parsed.PeerAS,
						PeerBGPID:    parsed.PeerBGPID,
						IsPostPolicy: parsed.IsPostPolicy,
						TableName:    tableName,
						AFI:          afi,
						IsEOR:        true,
					})
					finalAction = actionAdjRibInEOR
					continue
				}

				tableName := parsed.TableName
				if tableName == "UNKNOWN" {
					tableName = ""
				}

				for _, ev := range events {
					afiStr := fmt.Sprintf("%d", ev.AFI)
					metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, afiStr, "adj_"+ev.Action).Inc()

					routes = append(routes, &ParsedRoute{
						RouterID:     routerID,
						PeerAddress:  parsed.PeerAddress,
						PeerAS:       parsed.PeerAS,
						PeerBGPID:    parsed.PeerBGPID,
						IsPostPolicy: parsed.IsPostPolicy,
						TableName:    tableName,
						AFI:          ev.AFI,
						Prefix:       ev.Prefix,
						PathID:       ev.PathID,
						Action:       ev.Action,
						Nexthop:      ev.Nexthop,
						ASPath:       ev.ASPath,
						Origin:       ev.Origin,
						LocalPref:    ev.LocalPref,
						MED:          ev.MED,
						OriginASN:    bgp.OriginASN(ev.ASPath),
						CommStd:      ev.CommStd,
						CommExt:      ev.CommExt,
						CommLarge:    ev.CommLarge,
					})
				}
				finalAction = actionAdjRibInRoute
			}
		}
	}

	if len(routes) == 0 {
		return nil, actionRoute
	}

	return routes, finalAction
}

func (p *Pipeline) flushAll(ctx context.Context, batch, adjBatch []*ParsedRoute, records []*kgo.Record, flushed chan<- []*kgo.Record) error {
	if err := p.writer.FlushBatch(ctx, batch); err != nil {
		return err
	}
	if err := p.writer.FlushAdjRibInBatch(ctx, adjBatch); err != nil {
		return err
	}

	// Signal successful flush for offset commit.
	select {
	case flushed <- records:
	case <-ctx.Done():
	}

	return nil
}
