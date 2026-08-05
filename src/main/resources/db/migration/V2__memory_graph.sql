-- BAT security v2 — memory graph persistence

CREATE TABLE IF NOT EXISTS memory_node (
    node_id       UUID PRIMARY KEY,
    node_key      TEXT NOT NULL,
    node_type     TEXT NOT NULL,
    label         TEXT,
    properties    TEXT NOT NULL DEFAULT '{}',
    base_weight   DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    last_seen_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (node_type, node_key)
);

CREATE INDEX IF NOT EXISTS idx_memory_node_key ON memory_node (node_key);
CREATE INDEX IF NOT EXISTS idx_memory_node_type ON memory_node (node_type);

CREATE TABLE IF NOT EXISTS memory_edge (
    edge_id         UUID PRIMARY KEY,
    source_node_id  UUID NOT NULL,
    target_node_id  UUID NOT NULL,
    relation        TEXT NOT NULL,
    weight          DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    last_observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (source_node_id, target_node_id, relation)
);

CREATE INDEX IF NOT EXISTS idx_memory_edge_source ON memory_edge (source_node_id);
CREATE INDEX IF NOT EXISTS idx_memory_edge_target ON memory_edge (target_node_id);

CREATE TABLE IF NOT EXISTS behaviour_baseline (
    entity_id        TEXT NOT NULL,
    feature_name     TEXT NOT NULL,
    mean             DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    m2               DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    sample_count     BIGINT NOT NULL DEFAULT 0,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (entity_id, feature_name)
);
