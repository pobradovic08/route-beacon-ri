package history

import (
	"context"
	"encoding/binary"
	"fmt"
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
	maxPayloadBytes int
	logger          *zap.Logger
	asnCache        map[string]uint32
	routerMeta      map[string]config.RouterMeta
	// routerIDCache maps OBMP router hash → real router BGP ID (from Peer Up
	// Sent OPEN). goBMP generates a unique router hash per (router, peer)
	// combination, making it a reliable correlation key across message types.
	routerIDCache map[string]string
}

func NewPipeline(writer *Writer, batchSize, flushIntervalMs, maxPayloadBytes int, logger *zap.Logger, routerMeta map[string]config.RouterMeta) *Pipeline {
	if routerMeta == nil {
		routerMeta = make(map[string]config.RouterMeta)
	}
	return &Pipeline{
		writer:          writer,
		batchSize:       batchSize,
		flushInterval:   time.Duration(flushIntervalMs) * time.Millisecond,
		maxPayloadBytes: maxPayloadBytes,
		logger:          logger,
		asnCache:        make(map[string]uint32),
		routerMeta:      routerMeta,
		routerIDCache:   make(map[string]string),
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
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shutdownCancel()
				p.flush(shutdownCtx, batch, batchRecords, flushed)
			}
			return

		case recs, ok := <-records:
			if !ok {
				if len(batchRecords) > 0 {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					p.flush(shutdownCtx, batch, batchRecords, flushed)
				}
				return
			}

			for _, rec := range recs {
				rows := p.processRecord(ctx, rec)
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
			// grow beyond 10x the configured size, drop the in-memory
			// batch to prevent unbounded memory growth. Offsets are NOT
			// committed so records will be re-consumed on restart.
			if len(batchRecords) >= p.batchSize*10 {
				p.logger.Error("dropping oversized batch after repeated flush failures",
					zap.Int("dropped_records", len(batchRecords)),
					zap.Int("dropped_rows", len(batch)),
				)
				metrics.BatchDroppedTotal.WithLabelValues("history").Inc()
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

func (p *Pipeline) processRecord(ctx context.Context, rec *kgo.Record) []*HistoryRow {
	// Step 1: Decode OpenBMP frame.
	bmpBytes, err := bmp.DecodeOpenBMPFrame(rec.Value, p.maxPayloadBytes)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("openbmp", "decode").Inc()
		p.logger.Warn("failed to decode OpenBMP frame",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil
	}

	// A single raw Kafka record may contain multiple concatenated BMP
	// messages (goBMP bundles an entire TCP read into one record).
	msgs, err := bmp.ParseAll(bmpBytes)
	if err != nil {
		metrics.ParseErrorsTotal.WithLabelValues("bmp", "parse").Inc()
		p.logger.Warn("failed to parse BMP messages",
			zap.String("topic", rec.Topic),
			zap.Error(err),
		)
		return nil
	}

	obmpRouterIP := bmp.RouterIPFromOpenBMPV17(rec.Value)
	obmpRouterHash := bmp.RouterHashFromOpenBMPV17(rec.Value)

	var rows []*HistoryRow
	for _, parsed := range msgs {
		if parsed.MsgType == bmp.MsgTypePeerUp {
			if parsed.IsLocRIB && parsed.LocalBGPID != "" {
				p.processLocRIBPeerUp(ctx, rec, parsed)
			} else if !parsed.IsLocRIB && parsed.LocalASN > 0 {
				p.processPeerUpASN(ctx, rec, parsed, obmpRouterIP, obmpRouterHash)
			}
			continue
		}
		if parsed.MsgType != bmp.MsgTypeRouteMonitoring || parsed.BGPData == nil {
			continue
		}

		// Validate BMP message bounds.
		msgEnd := parsed.Offset + bmp.CommonHeaderSize
		if msgEnd > len(bmpBytes) {
			continue
		}
		msgLen := int(binary.BigEndian.Uint32(bmpBytes[parsed.Offset+1 : parsed.Offset+5]))
		if parsed.Offset+msgLen > len(bmpBytes) {
			continue
		}
		bmpMsgBytes := bmpBytes[parsed.Offset : parsed.Offset+msgLen]

		// ParseUpdateAutoDetect handles routers that send Add-Path
		// encoded NLRI without setting the F-bit (e.g. Arista cEOS).
		events, _, err := bgp.ParseUpdateAutoDetect(parsed.BGPData, parsed.HasAddPath)
		if err != nil {
			metrics.ParseErrorsTotal.WithLabelValues("bgp", "parse").Inc()
			p.logger.Warn("failed to parse BGP UPDATE",
				zap.String("topic", rec.Topic),
				zap.Error(err),
			)
			continue
		}
		if len(events) == 0 {
			continue
		}

		// Router ID: For Loc-RIB, use per-peer header BGP ID. For
		// non-Loc-RIB, use OBMP header router IP (the BMP speaker).
		var routerID string
		if parsed.IsLocRIB {
			peerHdrOffset := parsed.Offset + bmp.CommonHeaderSize
			routerID = bmp.RouterIDFromPeerHeader(bmpBytes[peerHdrOffset:])
			if routerID == "" || routerID == "::" || routerID == "0.0.0.0" {
				if obmpRouterIP != "" {
					routerID = obmpRouterIP
				}
			}
		} else {
			routerID = obmpRouterIP
			if obmpRouterHash != "" {
				if cached, ok := p.routerIDCache[obmpRouterHash]; ok {
					routerID = cached
				}
			}
		}

		tableName := parsed.TableName
		if !parsed.IsLocRIB && tableName == "UNKNOWN" {
			tableName = ""
		}

		for _, ev := range events {
			// Per-prefix event_id: hash BMP msg bytes + suffix.
			// For non-Loc-RIB, include peer_address in the hash to
			// distinguish the same prefix from different peers.
			var suffix []byte
			if !parsed.IsLocRIB {
				suffix = []byte(parsed.PeerAddress + "/" + ev.Prefix + "/" + ev.Action)
			} else {
				suffix = []byte(ev.Prefix + "/" + ev.Action)
			}
			perPrefixData := make([]byte, len(bmpMsgBytes)+len(suffix))
			copy(perPrefixData, bmpMsgBytes)
			copy(perPrefixData[len(bmpMsgBytes):], suffix)
			rowEventID := ComputeEventID(perPrefixData)

			afiStr := fmt.Sprintf("%d", ev.AFI)
			metrics.KafkaMessagesTotal.WithLabelValues("history", rec.Topic, afiStr, ev.Action).Inc()

			rows = append(rows, &HistoryRow{
				EventID:      rowEventID,
				RouterID:     routerID,
				TableName:    tableName,
				Event:        ev,
				BMPRaw:       bmpMsgBytes,
				Topic:        rec.Topic,
				PeerAddress:  parsed.PeerAddress,
				PeerAS:       parsed.PeerAS,
				PeerBGPID:    parsed.PeerBGPID,
				IsPostPolicy: parsed.IsPostPolicy,
				IsLocRIB:     parsed.IsLocRIB,
			})
		}
	}

	return rows
}

func (p *Pipeline) processLocRIBPeerUp(ctx context.Context, rec *kgo.Record, parsed *bmp.ParsedBMP) {
	metrics.KafkaMessagesTotal.WithLabelValues("history", rec.Topic, "", "peer_up_locrib").Inc()

	routerID := parsed.LocalBGPID

	if p.writer == nil || p.writer.pool == nil {
		p.logger.Info("router registered from Loc-RIB Peer Up (no db)",
			zap.String("router_id", routerID),
		)
		return
	}

	meta := p.routerMeta[routerID]
	if err := UpsertRouter(ctx, p.writer.pool, routerID, routerID, "", "", nil, meta.Name, meta.Location); err != nil {
		p.logger.Warn("failed to upsert router from Loc-RIB Peer Up",
			zap.String("router_id", routerID),
			zap.Error(err),
		)
		return
	}

	p.logger.Info("router registered from Loc-RIB Peer Up",
		zap.String("router_id", routerID),
	)
}

func (p *Pipeline) processPeerUpASN(ctx context.Context, rec *kgo.Record, parsed *bmp.ParsedBMP, obmpRouterIP, obmpRouterHash string) {
	// Use the BGP Identifier from the Sent OPEN as the router ID.
	// The OBMP header's router IP is unreliable for Peer Up messages:
	// goBMP populates it with the monitored peer's address, not the
	// BMP speaker's address. The Sent OPEN's BGP ID is the speaker's own
	// identifier — matching what the Initiation handler stores.
	routerID := parsed.LocalBGPID
	if routerID == "" {
		routerID = obmpRouterIP
	}
	if routerID == "" {
		return
	}
	// Cache: OBMP router hash → real router BGP ID
	if obmpRouterHash != "" {
		p.routerIDCache[obmpRouterHash] = routerID
	}
	routerIP := routerID

	if p.asnCache[routerID] == parsed.LocalASN {
		return
	}

	asn := int64(parsed.LocalASN)
	if p.writer == nil || p.writer.pool == nil {
		p.asnCache[routerID] = parsed.LocalASN
		metrics.KafkaMessagesTotal.WithLabelValues("history", rec.Topic, "", "peer_up_asn").Inc()
		p.logger.Info("router ASN extracted from BMP Peer Up (no db)",
			zap.String("router_id", routerID),
			zap.Uint32("as_number", parsed.LocalASN),
		)
		return
	}
	meta := p.routerMeta[routerID]
	if err := UpsertRouter(ctx, p.writer.pool, routerID, routerIP, "", "", &asn, meta.Name, meta.Location); err != nil {
		p.logger.Warn("failed to upsert router ASN from peer up",
			zap.String("router_id", routerID),
			zap.Uint32("as_number", parsed.LocalASN),
			zap.Error(err),
		)
		return
	}

	p.asnCache[routerID] = parsed.LocalASN
	metrics.KafkaMessagesTotal.WithLabelValues("history", rec.Topic, "", "peer_up_asn").Inc()
	p.logger.Info("router ASN extracted from BMP Peer Up",
		zap.String("router_id", routerID),
		zap.Uint32("as_number", parsed.LocalASN),
	)
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
		if !row.IsLocRIB {
			continue
		}
		k := key{row.RouterID, row.TableName, row.Event.AFI}
		if seen[k] {
			continue
		}
		seen[k] = true

		if err := p.writer.UpdateSyncStatus(ctx, row.RouterID, row.TableName, row.Event.AFI); err != nil {
			p.logger.Warn("failed to update sync status for raw msg",
				zap.String("router_id", row.RouterID),
				zap.Error(err),
			)
		}

		afiStr := fmt.Sprintf("%d", row.Event.AFI)
		metrics.LastMsgTimestamp.WithLabelValues("history", row.RouterID, row.TableName, afiStr).SetToCurrentTime()
	}
}
