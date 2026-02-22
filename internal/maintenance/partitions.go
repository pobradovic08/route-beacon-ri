package maintenance

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

var validPartitionName = regexp.MustCompile(`^route_events_\d{8}$`)

type PartitionManager struct {
	pool          *pgxpool.Pool
	retentionDays int
	timezone      string
	logger        *zap.Logger
}

func NewPartitionManager(pool *pgxpool.Pool, retentionDays int, timezone string, logger *zap.Logger) *PartitionManager {
	return &PartitionManager{
		pool:          pool,
		retentionDays: retentionDays,
		timezone:      timezone,
		logger:        logger,
	}
}

func (pm *PartitionManager) Run(ctx context.Context) error {
	if err := pm.CreatePartitions(ctx); err != nil {
		return fmt.Errorf("creating partitions: %w", err)
	}
	if err := pm.DropOldPartitions(ctx); err != nil {
		return fmt.Errorf("dropping old partitions: %w", err)
	}
	if err := pm.RefreshSummary(ctx); err != nil {
		return fmt.Errorf("refreshing route summary: %w", err)
	}
	return nil
}

// RefreshSummary refreshes the route_summary and adj_rib_in_summary materialized views concurrently.
func (pm *PartitionManager) RefreshSummary(ctx context.Context) error {
	_, err := pm.pool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY route_summary")
	if err != nil {
		pm.logger.Warn("failed to refresh route_summary (may not exist yet)", zap.Error(err))
	}
	_, err = pm.pool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY adj_rib_in_summary")
	if err != nil {
		pm.logger.Warn("failed to refresh adj_rib_in_summary (may not exist yet)", zap.Error(err))
	}
	return nil
}

// CreatePartitions creates daily partitions for today and tomorrow using the configured timezone.
func (pm *PartitionManager) CreatePartitions(ctx context.Context) error {
	loc, err := time.LoadLocation(pm.timezone)
	if err != nil {
		return fmt.Errorf("loading timezone %s: %w", pm.timezone, err)
	}

	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	tomorrow := today.AddDate(0, 0, 1)
	dayAfter := today.AddDate(0, 0, 2)

	if err := pm.createPartition(ctx, today, tomorrow); err != nil {
		return err
	}
	if err := pm.createPartition(ctx, tomorrow, dayAfter); err != nil {
		return err
	}
	return nil
}

func (pm *PartitionManager) createPartition(ctx context.Context, from, to time.Time) error {
	name := fmt.Sprintf("route_events_%s", from.Format("20060102"))
	safeName := pgx.Identifier{name}.Sanitize()
	fromStr := from.UTC().Format("2006-01-02 15:04:05+00")
	toStr := to.UTC().Format("2006-01-02 15:04:05+00")

	createSQL := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF route_events FOR VALUES FROM ('%s') TO ('%s')`,
		safeName, fromStr, toStr,
	)

	if _, err := pm.pool.Exec(ctx, createSQL); err != nil {
		return fmt.Errorf("creating partition %s: %w", name, err)
	}
	pm.logger.Info("partition ensured", zap.String("partition", name))

	// Create per-partition indexes using sanitized names.
	safeIdxPrefix := pgx.Identifier{fmt.Sprintf("idx_%s_prefix_history", name)}.Sanitize()
	safeIdxChurn := pgx.Identifier{fmt.Sprintf("idx_%s_router_churn", name)}.Sanitize()

	prefixIdx := fmt.Sprintf(
		`CREATE INDEX IF NOT EXISTS %s ON %s (router_id, table_name, afi, prefix, ingest_time DESC)`,
		safeIdxPrefix, safeName,
	)
	churnIdx := fmt.Sprintf(
		`CREATE INDEX IF NOT EXISTS %s ON %s (router_id, table_name, afi, ingest_time DESC)`,
		safeIdxChurn, safeName,
	)

	if _, err := pm.pool.Exec(ctx, prefixIdx); err != nil {
		return fmt.Errorf("creating prefix_history index on %s: %w", name, err)
	}
	if _, err := pm.pool.Exec(ctx, churnIdx); err != nil {
		return fmt.Errorf("creating router_churn index on %s: %w", name, err)
	}

	return nil
}

// DropOldPartitions drops partitions older than the configured retention period.
func (pm *PartitionManager) DropOldPartitions(ctx context.Context) error {
	loc, err := time.LoadLocation(pm.timezone)
	if err != nil {
		return fmt.Errorf("loading timezone %s: %w", pm.timezone, err)
	}

	// Cutoff: retention_days ago in the configured timezone, then converted to a date.
	cutoff := time.Now().In(loc).AddDate(0, 0, -pm.retentionDays)
	cutoffDate := time.Date(cutoff.Year(), cutoff.Month(), cutoff.Day(), 0, 0, 0, 0, loc)

	// List existing partitions of route_events.
	rows, err := pm.pool.Query(ctx,
		`SELECT inhrelid::regclass::text FROM pg_inherits WHERE inhparent = 'route_events'::regclass`)
	if err != nil {
		return fmt.Errorf("listing partitions: %w", err)
	}
	defer rows.Close()

	var partitions []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scanning partition name: %w", err)
		}
		partitions = append(partitions, name)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating partitions: %w", err)
	}

	for _, name := range partitions {
		if !validPartitionName.MatchString(name) {
			pm.logger.Warn("skipping partition with unexpected name", zap.String("partition", name))
			continue
		}

		// Parse date from partition name: route_events_YYYYMMDD
		dateStr := name[len(name)-8:]
		partDate, err := time.ParseInLocation("20060102", dateStr, loc)
		if err != nil {
			pm.logger.Warn("cannot parse partition date", zap.String("partition", name))
			continue
		}

		if partDate.Before(cutoffDate) {
			safeName := pgx.Identifier{name}.Sanitize()
			dropSQL := fmt.Sprintf("DROP TABLE IF EXISTS %s", safeName)
			if _, err := pm.pool.Exec(ctx, dropSQL); err != nil {
				return fmt.Errorf("dropping partition %s: %w", name, err)
			}
			pm.logger.Info("dropped old partition", zap.String("partition", name), zap.Time("cutoff", cutoffDate))
		}
	}

	return nil
}
