#!/usr/bin/env bash
set -e

EXPECTED=200
TIMEOUT=120
INTERVAL=5
COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

elapsed=0
while [ "$elapsed" -lt "$TIMEOUT" ]; do
    count=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T postgres \
        psql -U rib -d rib -t -A -c "SELECT count(*) FROM current_routes WHERE afi = 4;" 2>/dev/null || echo "0")
    count=$(echo "$count" | tr -d '[:space:]')

    if [ "$count" -ge "$EXPECTED" ]; then
        echo "PASS: $count/$EXPECTED routes ingested into current_routes"
        exit 0
    fi

    echo "Waiting... $count/$EXPECTED routes (${elapsed}s/${TIMEOUT}s)"
    sleep "$INTERVAL"
    elapsed=$((elapsed + INTERVAL))
done

echo "FAIL: Only $count/$EXPECTED routes after ${TIMEOUT}s timeout"
exit 1
