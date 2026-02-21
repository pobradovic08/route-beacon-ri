package history

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

const upsertRouterSQL = `
INSERT INTO routers (router_id, router_ip, hostname, as_number, description, first_seen, last_seen)
VALUES ($1, $2, $3, $4, $5, now(), now())
ON CONFLICT (router_id) DO UPDATE SET
    router_ip   = COALESCE(EXCLUDED.router_ip, routers.router_ip),
    hostname    = COALESCE(EXCLUDED.hostname, routers.hostname),
    as_number   = COALESCE(EXCLUDED.as_number, routers.as_number),
    description = COALESCE(EXCLUDED.description, routers.description),
    last_seen   = now()`

// UpsertRouter inserts or updates router metadata from a BMP Initiation message.
// Uses COALESCE to preserve non-null values — a field already populated from a
// previous session won't be overwritten with NULL.
// Errors are returned for logging but should be treated as non-fatal to the pipeline.
func UpsertRouter(ctx context.Context, pool *pgxpool.Pool, routerID, routerIP, hostname, description string) error {
	_, err := pool.Exec(ctx, upsertRouterSQL,
		routerID,
		nilIfEmptyStr(routerIP),
		nilIfEmptyStr(hostname),
		nil, // as_number — not available from BMP Initiation TLVs.
		nilIfEmptyStr(description),
	)
	return err
}

func nilIfEmptyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
