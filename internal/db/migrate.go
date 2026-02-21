package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`

func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationsDir string, logger *zap.Logger) error {
	// Acquire a dedicated connection for advisory lock affinity.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection for migration: %w", err)
	}
	defer conn.Release()

	// Acquire advisory lock to prevent concurrent migrations.
	const migrationLockID int64 = 0x726962696E676573 // "ribinges" as int64
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	defer conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockID)

	// Ensure the schema_migrations table exists.
	if _, err := conn.Exec(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	// Read migration files.
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("reading migrations directory %s: %w", migrationsDir, err)
	}

	type migration struct {
		version  int
		filename string
	}

	var migrations []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// Extract version number from filename: NNNN_description.sql
		parts := strings.SplitN(e.Name(), "_", 2)
		if len(parts) < 2 {
			continue
		}
		ver, err := strconv.Atoi(parts[0])
		if err != nil {
			logger.Warn("skipping non-numeric migration file", zap.String("file", e.Name()))
			continue
		}
		migrations = append(migrations, migration{version: ver, filename: e.Name()})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	// Get applied versions.
	applied := make(map[int]bool)
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("querying applied migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("scanning migration version: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating migration rows: %w", err)
	}

	// Apply pending migrations in order.
	for _, m := range migrations {
		if applied[m.version] {
			logger.Debug("migration already applied", zap.Int("version", m.version))
			continue
		}

		sql, err := os.ReadFile(filepath.Join(migrationsDir, m.filename))
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", m.filename, err)
		}

		logger.Info("applying migration", zap.Int("version", m.version), zap.String("file", m.filename))

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning transaction for migration %d: %w", m.version, err)
		}

		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("executing migration %d (%s): %w", m.version, m.filename, err)
		}

		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", m.version); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("recording migration %d: %w", m.version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing migration %d: %w", m.version, err)
		}

		logger.Info("migration applied", zap.Int("version", m.version))
	}

	return nil
}
