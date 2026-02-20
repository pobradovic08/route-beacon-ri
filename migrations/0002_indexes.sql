-- GiST index for LPM queries on current_routes
CREATE INDEX IF NOT EXISTS idx_current_routes_prefix_gist
    ON current_routes USING GIST (prefix inet_ops);

-- B-tree for router/table/afi scans
CREATE INDEX IF NOT EXISTS idx_current_routes_router_table_afi
    ON current_routes (router_id, table_name, afi);
