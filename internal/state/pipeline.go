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
	// routerIDCache maps OBMP router hash → real router BGP ID (from Peer Up
	// Sent OPEN). goBMP generates a unique router hash per (router, peer)
	// combination, making it a reliable correlation key across message types.
	routerIDCache map[string]string
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
		routerIDCache:   make(map[string]string),
	}
}

type recordAction int

const (
	actionRoute            recordAction = iota
	actionEOR
	actionPeerDown
	actionAdjRibInRoute    // Adj-RIB-In route add/withdraw
	actionAdjRibInEOR      // Adj-RIB-In End-of-RIB
	actionAdjRibInPeerDown // Non-Loc-RIB peer down
)

// processedRecord holds the results of processing a single Kafka record.
// Routes are separated by type (Loc-RIB vs Adj-RIB-In) so Run() can
// dispatch them to the correct batch without last-writer-wins corruption
// when a single raw record contains both Loc-RIB and non-Loc-RIB messages.
type processedRecord struct {
	locRoutes []*ParsedRoute
	adjRoutes []*ParsedRoute
	locAction recordAction
	adjAction recordAction
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
				result := p.processRecord(ctx, rec)

				if len(result.locRoutes) == 0 && len(result.adjRoutes) == 0 {
					// Always track the record for offset commit, even if
					// parsing failed or the message was filtered. This
					// prevents unparseable records from stalling partition
					// progress.
					batchRecords = append(batchRecords, rec)
					continue
				}

				skipRecord := false
				needsImmediateCommit := false

				// --- Handle Adj-RIB-In first ---
				// Process adj routes before Loc-RIB to ensure pending adj data
				// is flushed before a Loc-RIB PeerDown purges it.
				if len(result.adjRoutes) > 0 {
					switch result.adjAction {
					case actionAdjRibInRoute:
						adjBatch = append(adjBatch, result.adjRoutes...)

					case actionAdjRibInEOR:
						// Separate non-EOR routes from EOR markers
						// and add them to adjBatch before flushing.
						for _, r := range result.adjRoutes {
							if !r.IsEOR {
								adjBatch = append(adjBatch, r)
							}
						}
						if len(adjBatch) > 0 {
							if err := p.writer.FlushAdjRibInBatch(ctx, adjBatch); err != nil {
								p.logger.Error("pre-adj-eor flush failed", zap.Error(err))
								skipRecord = true
								break
							}
							adjBatch = nil
						}
						eorFailed := false
						for _, r := range result.adjRoutes {
							if !r.IsEOR {
								continue
							}
							if err := p.writer.HandleAdjRibInEOR(ctx, r.RouterID, r.PeerAddress, r.TableName, r.AFI); err != nil {
								p.logger.Error("adj_rib_in EOR handling failed", zap.Error(err))
								eorFailed = true
							}
						}
						if eorFailed {
							skipRecord = true
						} else {
							needsImmediateCommit = true
						}

					case actionAdjRibInPeerDown:
						// Flush pending adj batch to persist routes from other routers.
						if len(adjBatch) > 0 {
							if err := p.writer.FlushAdjRibInBatch(ctx, adjBatch); err != nil {
								p.logger.Error("pre-adj-peerdown flush failed", zap.Error(err))
								skipRecord = true
								break
							}
							adjBatch = nil
						}
						if err := p.writer.HandleAdjRibInPeerDown(ctx, result.adjRoutes[0].RouterID, result.adjRoutes[0].PeerAddress); err != nil {
							p.logger.Error("adj_rib_in peer down failed", zap.Error(err))
						}
						needsImmediateCommit = true
					}
				}

				if skipRecord {
					continue
				}

				// --- Handle Loc-RIB ---
				if len(result.locRoutes) > 0 {
					switch result.locAction {
					case actionRoute:
						batch = append(batch, result.locRoutes...)

					case actionEOR:
						// A raw record may contain both regular routes and
						// EOR markers. Separate them, flush routes first,
						// then handle each EOR.
						for _, r := range result.locRoutes {
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
						for _, r := range result.locRoutes {
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
						needsImmediateCommit = true

					case actionPeerDown:
						// Flush pending adj batch to persist routes from other routers
						// before clearing (R3-H2 fix).
						if len(adjBatch) > 0 {
							if err := p.writer.FlushAdjRibInBatch(ctx, adjBatch); err != nil {
								p.logger.Error("pre-peerdown adj flush failed", zap.Error(err))
							}
							adjBatch = nil
						}
						// Flush pending Loc-RIB routes to DB before session termination.
						if len(batch) > 0 {
							if err := p.writer.FlushBatch(ctx, batch); err != nil {
								p.logger.Error("pre-peerdown flush failed", zap.Error(err))
								continue
							}
							batch = nil
						}
						if err := p.writer.HandleSessionTermination(ctx, result.locRoutes[0].RouterID, result.locRoutes[0].TableName); err != nil {
							p.logger.Error("session termination failed", zap.Error(err))
						} else {
							// Also purge all adj_rib_in for the router since BMP session loss
							// means all peer monitoring data is stale.
							if err := p.writer.HandleAdjRibInSessionTermination(ctx, result.locRoutes[0].RouterID); err != nil {
								p.logger.Error("adj_rib_in session purge failed", zap.Error(err))
							}
						}
						needsImmediateCommit = true
					}
				}

				batchRecords = append(batchRecords, rec)

				if needsImmediateCommit && len(batchRecords) > 0 {
					select {
					case flushed <- batchRecords:
					case <-ctx.Done():
					}
					batchRecords = nil
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

func (p *Pipeline) processRecord(ctx context.Context, rec *kgo.Record) *processedRecord {
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
		return &processedRecord{}
	}

	// Filter: only process Loc-RIB messages.
	if !parsed.IsLocRIB {
		return &processedRecord{}
	}

	afiStr := fmt.Sprintf("%d", parsed.AFI)
	metrics.KafkaMessagesTotal.WithLabelValues("state", topic, afiStr, parsed.Action).Inc()
	metrics.LastMsgTimestamp.WithLabelValues("state", parsed.RouterID, parsed.TableName, afiStr).SetToCurrentTime()

	if parsed.IsEOR {
		return &processedRecord{
			locRoutes: []*ParsedRoute{parsed},
			locAction: actionEOR,
		}
	}

	return &processedRecord{
		locRoutes: []*ParsedRoute{parsed},
		locAction: actionRoute,
	}
}

func (p *Pipeline) processPeerRecord(ctx context.Context, rec *kgo.Record) *processedRecord {
	pe, err := DecodePeerMessage(rec.Value)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("json", "peer_decode").Inc()
		p.logger.Warn("failed to decode peer message",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return &processedRecord{}
	}

	if !pe.IsLocRIB {
		return &processedRecord{}
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
		return &processedRecord{}
	}

	if pe.Action == "peer_down" {
		metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "peer_down").Inc()
		return &processedRecord{
			locRoutes: []*ParsedRoute{{RouterID: pe.RouterID, TableName: pe.TableName}},
			locAction: actionPeerDown,
		}
	}

	return &processedRecord{}
}

func (p *Pipeline) processRawRecord(ctx context.Context, rec *kgo.Record) *processedRecord {
	bmpBytes, err := bmp.DecodeOpenBMPFrame(rec.Value, p.maxPayloadBytes)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("raw", "openbmp_decode").Inc()
		p.logger.Warn("failed to decode OpenBMP frame",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return &processedRecord{}
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
		return &processedRecord{}
	}

	// Extract router IP and router hash from the OpenBMP v1.7 header.
	// Router IP is a fallback for Loc-RIB identity. Router hash is the
	// correlation key for non-Loc-RIB messages (unique per router+peer).
	obmpRouterIP := bmp.RouterIPFromOpenBMPV17(rec.Value)
	obmpRouterHash := bmp.RouterHashFromOpenBMPV17(rec.Value)

	var result processedRecord

msgLoop:
	for _, parsed := range msgs {
		if parsed.IsLocRIB {
			// --- Loc-RIB path (peer type 3) ---
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
				result.locAction = actionPeerDown
				result.locRoutes = append(result.locRoutes, &ParsedRoute{RouterID: routerID, TableName: parsed.TableName})
				break msgLoop
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
				result.locRoutes = append(result.locRoutes, &ParsedRoute{
					RouterID:  routerID,
					TableName: parsed.TableName,
					AFI:       afi,
					IsLocRIB:  true,
					IsEOR:     true,
				})
				result.locAction = actionEOR
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
				result.locRoutes = append(result.locRoutes, r)
			}
			if result.locAction != actionEOR {
				result.locAction = actionRoute
			}
		} else {
			// --- Adj-RIB-In path (peer types 0/1/2) ---
			// goBMP populates the OBMP header router IP with the monitored
			// peer's address instead of the BMP speaker's for non-Loc-RIB
			// messages. Use routerIDCache keyed by OBMP router hash
			// (unique per router+peer) to resolve the real router identity.
			routerID := obmpRouterIP
			if obmpRouterHash != "" {
				if cached, ok := p.routerIDCache[obmpRouterHash]; ok {
					routerID = cached
				}
			}

			switch parsed.MsgType {
			case bmp.MsgTypePeerUp:
				// Non-Loc-RIB Peer Up: extract real router ID from Sent OPEN
				// BGP Identifier and cache it for subsequent messages.
				metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, "", "adj_peer_up").Inc()
				peerUpRouterID := parsed.LocalBGPID
				if peerUpRouterID == "" {
					peerUpRouterID = obmpRouterIP
				}
				if peerUpRouterID == "" {
					continue
				}
				// Cache: OBMP router hash → real router BGP ID
				if obmpRouterHash != "" {
					p.routerIDCache[obmpRouterHash] = peerUpRouterID
				}
				routerID = peerUpRouterID
				if p.writer != nil {
					for _, afi := range []int{4, 6} {
						if err := p.writer.UpdateAdjRibInSessionStart(ctx, peerUpRouterID, parsed.PeerAddress, afi); err != nil {
							p.logger.Error("UpdateAdjRibInSessionStart failed",
								zap.String("router_id", peerUpRouterID),
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
				result.adjAction = actionAdjRibInPeerDown
				result.adjRoutes = append(result.adjRoutes, &ParsedRoute{
					RouterID:     routerID,
					PeerAddress:  parsed.PeerAddress,
					PeerAS:       parsed.PeerAS,
					PeerBGPID:    parsed.PeerBGPID,
					IsPostPolicy: parsed.IsPostPolicy,
				})
				break msgLoop

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

					result.adjRoutes = append(result.adjRoutes, &ParsedRoute{
						RouterID:     routerID,
						PeerAddress:  parsed.PeerAddress,
						PeerAS:       parsed.PeerAS,
						PeerBGPID:    parsed.PeerBGPID,
						IsPostPolicy: parsed.IsPostPolicy,
						TableName:    tableName,
						AFI:          afi,
						IsEOR:        true,
					})
					result.adjAction = actionAdjRibInEOR
					continue
				}

				tableName := parsed.TableName
				if tableName == "UNKNOWN" {
					tableName = ""
				}

				for _, ev := range events {
					afiStr := fmt.Sprintf("%d", ev.AFI)
					metrics.KafkaMessagesTotal.WithLabelValues("state", rec.Topic, afiStr, "adj_"+ev.Action).Inc()

					r := &ParsedRoute{
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
					}
					if len(ev.Attrs) > 0 {
						attrs := make(map[string]any, len(ev.Attrs))
						for k, v := range ev.Attrs {
							attrs[k] = v
						}
						r.Attrs = attrs
					}
					result.adjRoutes = append(result.adjRoutes, r)
				}
				if result.adjAction != actionAdjRibInEOR {
					result.adjAction = actionAdjRibInRoute
				}
			}
		}
	}

	return &result
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
