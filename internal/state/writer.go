package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/route-beacon/rib-ingester/internal/metrics"
	"go.uber.org/zap"
)

type Writer struct {
	pool   *pgxpool.Pool
	logger *zap.Logger
}

func NewWriter(pool *pgxpool.Pool, logger *zap.Logger) *Writer {
	return &Writer{pool: pool, logger: logger}
}

// FlushBatch writes a batch of parsed routes to current_routes within a transaction.
func (w *Writer) FlushBatch(ctx context.Context, routes []*ParsedRoute) error {
	if len(routes) == 0 {
		return nil
	}

	start := time.Now()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var upserted, deleted int64

	for _, r := range routes {
		switch r.Action {
		case "A":
			n, err := w.upsertRoute(ctx, tx, r)
			if err != nil {
				return fmt.Errorf("upsert route: %w", err)
			}
			upserted += n
		case "D":
			n, err := w.deleteRoute(ctx, tx, r)
			if err != nil {
				return fmt.Errorf("delete route: %w", err)
			}
			deleted += n
		}

		// Update sync status for each route.
		if err := w.upsertSyncStatus(ctx, tx, r.RouterID, r.TableName, r.AFI); err != nil {
			return fmt.Errorf("upsert sync status: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	dur := time.Since(start).Seconds()
	metrics.DBWriteDuration.WithLabelValues("state", "batch").Observe(dur)
	metrics.DBRowsAffectedTotal.WithLabelValues("state", "current_routes", "upsert").Add(float64(upserted))
	metrics.DBRowsAffectedTotal.WithLabelValues("state", "current_routes", "delete").Add(float64(deleted))
	metrics.BatchSize.WithLabelValues("state").Observe(float64(len(routes)))

	return nil
}

// UpsertRouter inserts or updates router metadata from BMP Peer Up messages
// and operator-provided config (display_name, location).
func (w *Writer) UpsertRouter(ctx context.Context, routerID, routerIP, hostname, description, displayName, location string) error {
	_, err := w.pool.Exec(ctx, `
		INSERT INTO routers (router_id, router_ip, hostname, description, display_name, location, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, now(), now())
		ON CONFLICT (router_id) DO UPDATE SET
			router_ip    = COALESCE(EXCLUDED.router_ip, routers.router_ip),
			hostname     = COALESCE(EXCLUDED.hostname, routers.hostname),
			description  = COALESCE(EXCLUDED.description, routers.description),
			display_name = COALESCE(EXCLUDED.display_name, routers.display_name),
			location     = COALESCE(EXCLUDED.location, routers.location),
			last_seen    = now()`,
		routerID, nullableString(routerIP), nullableString(hostname), nullableString(description),
		nullableString(displayName), nullableString(location),
	)
	return err
}

func (w *Writer) upsertRoute(ctx context.Context, tx pgx.Tx, r *ParsedRoute) (int64, error) {
	var attrsJSON []byte
	if r.Attrs != nil {
		var err error
		attrsJSON, err = json.Marshal(r.Attrs)
		if err != nil {
			return 0, fmt.Errorf("marshal attrs: %w", err)
		}
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO current_routes (router_id, table_name, afi, prefix, path_id,
			nexthop, as_path, origin, localpref, med, origin_asn,
			communities_std, communities_ext, communities_large, attrs, first_seen, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, now(), now())
		ON CONFLICT (router_id, table_name, afi, prefix, path_id)
		DO UPDATE SET
			nexthop = EXCLUDED.nexthop,
			as_path = EXCLUDED.as_path,
			origin = EXCLUDED.origin,
			localpref = EXCLUDED.localpref,
			med = EXCLUDED.med,
			origin_asn = EXCLUDED.origin_asn,
			communities_std = EXCLUDED.communities_std,
			communities_ext = EXCLUDED.communities_ext,
			communities_large = EXCLUDED.communities_large,
			attrs = EXCLUDED.attrs,
			updated_at = now()`,
		r.RouterID, r.TableName, r.AFI, r.Prefix, r.PathID,
		nullableString(r.Nexthop), nullableString(r.ASPath), nullableString(r.Origin),
		r.LocalPref, r.MED, r.OriginASN,
		r.CommStd, r.CommExt, r.CommLarge, attrsJSON,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (w *Writer) deleteRoute(ctx context.Context, tx pgx.Tx, r *ParsedRoute) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM current_routes WHERE router_id = $1 AND table_name = $2 AND afi = $3 AND prefix = $4 AND path_id = $5`,
		r.RouterID, r.TableName, r.AFI, r.Prefix, r.PathID,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (w *Writer) upsertSyncStatus(ctx context.Context, tx pgx.Tx, routerID, tableName string, afi int) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO rib_sync_status (router_id, table_name, afi, last_parsed_msg_time, session_start_time, eor_seen, updated_at)
		VALUES ($1, $2, $3, now(), now(), false, now())
		ON CONFLICT (router_id, table_name, afi)
		DO UPDATE SET last_parsed_msg_time = now(), updated_at = now()`,
		routerID, tableName, afi,
	)
	return err
}

// HandleEOR updates sync status and purges stale routes after End-of-RIB.
func (w *Writer) HandleEOR(ctx context.Context, routerID, tableName string, afi int) error {
	start := time.Now()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Update EOR status.
	_, err = tx.Exec(ctx, `
		UPDATE rib_sync_status SET eor_seen = true, eor_time = now(), updated_at = now()
		WHERE router_id = $1 AND table_name = $2 AND afi = $3`,
		routerID, tableName, afi,
	)
	if err != nil {
		return fmt.Errorf("update eor status: %w", err)
	}

	// Get session_start_time for stale route purge.
	var sessionStart *time.Time
	err = tx.QueryRow(ctx,
		`SELECT session_start_time FROM rib_sync_status WHERE router_id = $1 AND table_name = $2 AND afi = $3`,
		routerID, tableName, afi,
	).Scan(&sessionStart)
	if err != nil {
		return fmt.Errorf("get session_start_time: %w", err)
	}

	if sessionStart != nil {
		tag, err := tx.Exec(ctx,
			`DELETE FROM current_routes WHERE router_id = $1 AND table_name = $2 AND afi = $3 AND updated_at < $4`,
			routerID, tableName, afi, *sessionStart,
		)
		if err != nil {
			return fmt.Errorf("purge stale routes: %w", err)
		}
		purged := tag.RowsAffected()
		if purged > 0 {
			metrics.RoutesPurgedTotal.WithLabelValues("eor_stale").Add(float64(purged))
			w.logger.Info("purged stale routes after EOR",
				zap.String("router_id", routerID),
				zap.String("table_name", tableName),
				zap.Int("afi", afi),
				zap.Int64("purged", purged),
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit eor tx: %w", err)
	}

	dur := time.Since(start).Seconds()
	metrics.DBWriteDuration.WithLabelValues("state", "eor").Observe(dur)
	metrics.EORSeen.WithLabelValues(routerID, tableName, fmt.Sprintf("%d", afi)).Set(1)

	return nil
}

// HandleSessionTermination purges all routes and sync status for a disconnected router.
// When tableName is non-empty, only the specific table is purged; otherwise all tables
// for the router are removed (legacy fallback).
func (w *Writer) HandleSessionTermination(ctx context.Context, routerID, tableName string) error {
	start := time.Now()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var purged int64
	if tableName != "" {
		// Scoped: purge only the specific table.
		tag, err := tx.Exec(ctx, `DELETE FROM current_routes WHERE router_id = $1 AND table_name = $2`, routerID, tableName)
		if err != nil {
			return fmt.Errorf("purge routes for router %s table %s: %w", routerID, tableName, err)
		}
		purged = tag.RowsAffected()

		_, err = tx.Exec(ctx, `DELETE FROM rib_sync_status WHERE router_id = $1 AND table_name = $2`, routerID, tableName)
		if err != nil {
			return fmt.Errorf("delete sync status for router %s table %s: %w", routerID, tableName, err)
		}
	} else {
		// Fallback: purge all tables for the router.
		tag, err := tx.Exec(ctx, `DELETE FROM current_routes WHERE router_id = $1`, routerID)
		if err != nil {
			return fmt.Errorf("purge routes for router %s: %w", routerID, err)
		}
		purged = tag.RowsAffected()

		_, err = tx.Exec(ctx, `DELETE FROM rib_sync_status WHERE router_id = $1`, routerID)
		if err != nil {
			return fmt.Errorf("delete sync status for router %s: %w", routerID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit session termination tx: %w", err)
	}

	dur := time.Since(start).Seconds()
	metrics.DBWriteDuration.WithLabelValues("state", "session_termination").Observe(dur)
	if purged > 0 {
		metrics.RoutesPurgedTotal.WithLabelValues("session_down").Add(float64(purged))
	}

	w.logger.Info("purged routes on session termination",
		zap.String("router_id", routerID),
		zap.String("table_name", tableName),
		zap.Int64("purged", purged),
	)

	return nil
}

// UpdateSessionStart sets the session_start_time for a new BMP session.
func (w *Writer) UpdateSessionStart(ctx context.Context, routerID, tableName string, afi int) error {
	_, err := w.pool.Exec(ctx, `
		INSERT INTO rib_sync_status (router_id, table_name, afi, session_start_time, eor_seen, updated_at)
		VALUES ($1, $2, $3, now(), false, now())
		ON CONFLICT (router_id, table_name, afi)
		DO UPDATE SET session_start_time = now(), eor_seen = false, eor_time = NULL, updated_at = now()`,
		routerID, tableName, afi,
	)
	return err
}

// FlushAdjRibInBatch writes a batch of Adj-RIB-In routes to adj_rib_in within a transaction.
func (w *Writer) FlushAdjRibInBatch(ctx context.Context, routes []*ParsedRoute) error {
	if len(routes) == 0 {
		return nil
	}

	start := time.Now()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var upserted, deleted int64

	for _, r := range routes {
		switch r.Action {
		case "A":
			n, err := w.upsertAdjRibInRoute(ctx, tx, r)
			if err != nil {
				return fmt.Errorf("upsert adj_rib_in route: %w", err)
			}
			upserted += n
		case "D":
			n, err := w.deleteAdjRibInRoute(ctx, tx, r)
			if err != nil {
				return fmt.Errorf("delete adj_rib_in route: %w", err)
			}
			deleted += n
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit adj_rib_in tx: %w", err)
	}

	dur := time.Since(start).Seconds()
	metrics.DBWriteDuration.WithLabelValues("state", "adj_batch").Observe(dur)
	metrics.DBRowsAffectedTotal.WithLabelValues("state", "adj_rib_in", "upsert").Add(float64(upserted))
	metrics.DBRowsAffectedTotal.WithLabelValues("state", "adj_rib_in", "delete").Add(float64(deleted))
	metrics.BatchSize.WithLabelValues("state_adj").Observe(float64(len(routes)))

	return nil
}

func (w *Writer) upsertAdjRibInRoute(ctx context.Context, tx pgx.Tx, r *ParsedRoute) (int64, error) {
	var attrsJSON []byte
	if r.Attrs != nil {
		var err error
		attrsJSON, err = json.Marshal(r.Attrs)
		if err != nil {
			return 0, fmt.Errorf("marshal attrs: %w", err)
		}
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO adj_rib_in (router_id, peer_address, peer_asn, peer_bgp_id, is_post_policy,
			table_name, afi, prefix, path_id,
			nexthop, as_path, origin, localpref, med, origin_asn,
			communities_std, communities_ext, communities_large, attrs,
			first_seen, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, now(), now())
		ON CONFLICT (router_id, peer_address, is_post_policy, table_name, afi, prefix, path_id)
		DO UPDATE SET
			peer_asn = EXCLUDED.peer_asn,
			peer_bgp_id = EXCLUDED.peer_bgp_id,
			nexthop = EXCLUDED.nexthop,
			as_path = EXCLUDED.as_path,
			origin = EXCLUDED.origin,
			localpref = EXCLUDED.localpref,
			med = EXCLUDED.med,
			origin_asn = EXCLUDED.origin_asn,
			communities_std = EXCLUDED.communities_std,
			communities_ext = EXCLUDED.communities_ext,
			communities_large = EXCLUDED.communities_large,
			attrs = EXCLUDED.attrs,
			updated_at = now()`,
		r.RouterID, r.PeerAddress, r.PeerAS, r.PeerBGPID, r.IsPostPolicy,
		r.TableName, r.AFI, r.Prefix, r.PathID,
		nullableString(r.Nexthop), nullableString(r.ASPath), nullableString(r.Origin),
		r.LocalPref, r.MED, r.OriginASN,
		r.CommStd, r.CommExt, r.CommLarge, attrsJSON,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (w *Writer) deleteAdjRibInRoute(ctx context.Context, tx pgx.Tx, r *ParsedRoute) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM adj_rib_in WHERE router_id = $1 AND peer_address = $2 AND is_post_policy = $3 AND table_name = $4 AND afi = $5 AND prefix = $6 AND path_id = $7`,
		r.RouterID, r.PeerAddress, r.IsPostPolicy, r.TableName, r.AFI, r.Prefix, r.PathID,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// HandleAdjRibInPeerDown removes all adj_rib_in routes and sync status for a specific peer
// within a single transaction (R3-M2: atomicity fix).
func (w *Writer) HandleAdjRibInPeerDown(ctx context.Context, routerID, peerAddress string) error {
	start := time.Now()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin adj peer down tx: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx,
		`DELETE FROM adj_rib_in WHERE router_id = $1 AND peer_address = $2`,
		routerID, peerAddress,
	)
	if err != nil {
		return fmt.Errorf("adj_rib_in peer down: %w", err)
	}

	_, err = tx.Exec(ctx,
		`DELETE FROM adj_rib_in_sync_status WHERE router_id = $1 AND peer_address = $2`,
		routerID, peerAddress,
	)
	if err != nil {
		return fmt.Errorf("adj_rib_in_sync_status peer down: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit adj peer down tx: %w", err)
	}

	dur := time.Since(start).Seconds()
	metrics.DBWriteDuration.WithLabelValues("state", "adj_peer_down").Observe(dur)
	purged := tag.RowsAffected()
	if purged > 0 {
		metrics.RoutesPurgedTotal.WithLabelValues("adj_peer_down").Add(float64(purged))
	}

	w.logger.Info("purged adj_rib_in routes on peer down",
		zap.String("router_id", routerID),
		zap.String("peer_address", peerAddress),
		zap.Int64("purged", purged),
	)

	return nil
}

// HandleAdjRibInSessionTermination removes ALL adj_rib_in routes and sync status for a router
// (called when BMP session terminates — Loc-RIB peer down or termination message).
// Uses a transaction for atomicity (R3-M2 fix).
func (w *Writer) HandleAdjRibInSessionTermination(ctx context.Context, routerID string) error {
	start := time.Now()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin adj session termination tx: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx,
		`DELETE FROM adj_rib_in WHERE router_id = $1`,
		routerID,
	)
	if err != nil {
		return fmt.Errorf("adj_rib_in session termination: %w", err)
	}

	_, err = tx.Exec(ctx,
		`DELETE FROM adj_rib_in_sync_status WHERE router_id = $1`,
		routerID,
	)
	if err != nil {
		return fmt.Errorf("adj_rib_in_sync_status session termination: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit adj session termination tx: %w", err)
	}

	dur := time.Since(start).Seconds()
	metrics.DBWriteDuration.WithLabelValues("state", "adj_session_termination").Observe(dur)
	purged := tag.RowsAffected()
	if purged > 0 {
		metrics.RoutesPurgedTotal.WithLabelValues("adj_session_down").Add(float64(purged))
	}

	w.logger.Info("purged all adj_rib_in routes on session termination",
		zap.String("router_id", routerID),
		zap.Int64("purged", purged),
	)

	return nil
}

// UpdateAdjRibInSessionStart records session start for stale route tracking.
// Called on non-Loc-RIB Peer Up.
func (w *Writer) UpdateAdjRibInSessionStart(ctx context.Context, routerID, peerAddress string, afi int) error {
	_, err := w.pool.Exec(ctx, `
		INSERT INTO adj_rib_in_sync_status (router_id, peer_address, afi, session_start_time, eor_seen, updated_at)
		VALUES ($1, $2, $3, now(), false, now())
		ON CONFLICT (router_id, peer_address, afi)
		DO UPDATE SET session_start_time = now(), eor_seen = false, eor_time = NULL, updated_at = now()`,
		routerID, peerAddress, afi,
	)
	return err
}

// HandleAdjRibInEOR updates sync status and purges stale adj_rib_in routes
// after End-of-RIB for a specific (router, peer, table, afi) scope.
func (w *Writer) HandleAdjRibInEOR(ctx context.Context, routerID, peerAddress, tableName string, afi int) error {
	start := time.Now()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Update EOR status.
	_, err = tx.Exec(ctx, `
		UPDATE adj_rib_in_sync_status SET eor_seen = true, eor_time = now(), updated_at = now()
		WHERE router_id = $1 AND peer_address = $2 AND afi = $3`,
		routerID, peerAddress, afi,
	)
	if err != nil {
		return fmt.Errorf("update adj eor status: %w", err)
	}

	// Get session_start_time for stale route purge.
	// If no sync-status row exists (e.g. missed/out-of-order Peer Up), skip
	// stale purge gracefully instead of hard-failing (R3-H7 fix).
	var sessionStart *time.Time
	err = tx.QueryRow(ctx,
		`SELECT session_start_time FROM adj_rib_in_sync_status WHERE router_id = $1 AND peer_address = $2 AND afi = $3`,
		routerID, peerAddress, afi,
	).Scan(&sessionStart)
	if errors.Is(err, pgx.ErrNoRows) {
		// No sync-status row — can't determine stale cutoff, skip purge.
		w.logger.Warn("no adj_rib_in_sync_status row for EOR, skipping stale purge",
			zap.String("router_id", routerID),
			zap.String("peer_address", peerAddress),
			zap.Int("afi", afi),
		)
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit adj eor tx: %w", err)
		}
		dur := time.Since(start).Seconds()
		metrics.DBWriteDuration.WithLabelValues("state", "adj_eor").Observe(dur)
		return nil
	}
	if err != nil {
		return fmt.Errorf("get adj session_start_time: %w", err)
	}

	if sessionStart != nil {
		tag, err := tx.Exec(ctx,
			`DELETE FROM adj_rib_in WHERE router_id = $1 AND peer_address = $2 AND table_name = $3 AND afi = $4 AND updated_at < $5`,
			routerID, peerAddress, tableName, afi, *sessionStart,
		)
		if err != nil {
			return fmt.Errorf("purge stale adj routes: %w", err)
		}
		purged := tag.RowsAffected()
		if purged > 0 {
			metrics.RoutesPurgedTotal.WithLabelValues("adj_eor_stale").Add(float64(purged))
			w.logger.Info("purged stale adj_rib_in routes after EOR",
				zap.String("router_id", routerID),
				zap.String("peer_address", peerAddress),
				zap.String("table_name", tableName),
				zap.Int("afi", afi),
				zap.Int64("purged", purged),
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit adj eor tx: %w", err)
	}

	dur := time.Since(start).Seconds()
	metrics.DBWriteDuration.WithLabelValues("state", "adj_eor").Observe(dur)

	return nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
