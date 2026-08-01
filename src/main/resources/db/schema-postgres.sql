-- =====================================================================
-- COGNESIS - Production PostgreSQL schema
-- Reference DDL for the Cognitive Security Decision Framework.
-- In the scaffold, the H2 dev profile uses db/schema-h2.sql; this file
-- is the authoritative target schema for PostgreSQL deployments.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------
-- OBSERVATORY: raw signals collected from evidence providers.
-- One row per signal fragment produced by an EvidenceProvider.
-- ---------------------------------------------------------------------
CREATE TABLE signal_observation (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id       TEXT        NOT NULL,
    entity_type     TEXT        NOT NULL,             -- DOMAIN | IP | USER | DEVICE | ...
    evidence_type   TEXT        NOT NULL,             -- DNS_DOMAIN_AGE | DNS_DGA | ...
    provenance      TEXT        NOT NULL,             -- OSINT | LIVE_TRAFFIC | ...
    strength        DOUBLE PRECISION NOT NULL,        -- 0..1 maliciousness evidence
    confidence      DOUBLE PRECISION NOT NULL,        -- 0..1 reliability of this signal
    explanation     TEXT,
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_signal_entity      ON signal_observation (entity_id, entity_type);
CREATE INDEX idx_signal_observed_at ON signal_observation (observed_at);
CREATE INDEX idx_signal_evidence    ON signal_observation (evidence_type);

-- ---------------------------------------------------------------------
-- FIDES: dynamic trust profiles (one per entity).
-- ---------------------------------------------------------------------
CREATE TABLE trust_profile (
    entity_id         TEXT PRIMARY KEY,
    entity_type       TEXT        NOT NULL,
    trust             DOUBLE PRECISION NOT NULL,       -- 0..1 (1 = fully trusted)
    trust_confidence  DOUBLE PRECISION NOT NULL,       -- 0..1
    observation_count BIGINT      NOT NULL DEFAULT 0,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE trust_event (
    id            BIGSERIAL PRIMARY KEY,
    entity_id     TEXT        NOT NULL,
    event_type    TEXT        NOT NULL,                -- POSITIVE | NEGATIVE | DECAY
    strength      DOUBLE PRECISION NOT NULL,
    narrative     TEXT,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_trust_event_entity ON trust_event (entity_id, occurred_at);

-- ---------------------------------------------------------------------
-- MNEMONIC: knowledge graph of remembered entities and relationships.
-- ---------------------------------------------------------------------
CREATE TABLE memory_node (
    node_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_key      TEXT NOT NULL,                        -- canonical identifier
    node_type     TEXT NOT NULL,                        -- DOMAIN | IP | USER | DEVICE | THREAT_ACTOR | ...
    label         TEXT,
    properties    JSONB NOT NULL DEFAULT '{}',
    base_weight   DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (node_type, node_key)
);

CREATE TABLE memory_edge (
    edge_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_node_id  UUID NOT NULL REFERENCES memory_node (node_id) ON DELETE CASCADE,
    target_node_id  UUID NOT NULL REFERENCES memory_node (node_id) ON DELETE CASCADE,
    relation        TEXT NOT NULL,                      -- RESOLVES_TO | CONNECTED_TO | OBSERVED_FOR | ...
    weight          DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    last_observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_node_id, target_node_id, relation)
);

CREATE INDEX idx_memory_edge_source ON memory_edge (source_node_id);
CREATE INDEX idx_memory_edge_target ON memory_edge (target_node_id);

CREATE TABLE behaviour_baseline (
    entity_id        TEXT PRIMARY KEY,
    entity_type      TEXT NOT NULL,
    feature_name     TEXT NOT NULL,
    mean             DOUBLE PRECISION NOT NULL,
    stddev           DOUBLE PRECISION NOT NULL,
    sample_count     BIGINT NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (entity_id, feature_name)
);

-- ---------------------------------------------------------------------
-- SYNAPSE: every decision is persisted with its full reasoning chain.
-- ---------------------------------------------------------------------
CREATE TABLE decision_log (
    decision_id         UUID PRIMARY KEY,
    entity_id           TEXT NOT NULL,
    entity_type         TEXT NOT NULL,
    decision            TEXT NOT NULL,                  -- ALLOW | WARN | MONITOR | BLOCK
    recommended_action  TEXT NOT NULL,
    risk_score          DOUBLE PRECISION NOT NULL,
    trust_score         DOUBLE PRECISION NOT NULL,
    confidence_score    DOUBLE PRECISION NOT NULL,
    business_impact     DOUBLE PRECISION NOT NULL,
    rationale           TEXT,
    reasoning_chain     JSONB NOT NULL,                 -- ordered list of ReasoningStep
    decision_request    JSONB,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_decision_log_entity   ON decision_log (entity_id);
CREATE INDEX idx_decision_log_time     ON decision_log (decided_at);
CREATE INDEX idx_decision_log_decision ON decision_log (decision);

-- ---------------------------------------------------------------------
-- PACT / POLICY: business policy rules consumed by the DNS engine.
-- ---------------------------------------------------------------------
CREATE TABLE policy_rule (
    rule_id      BIGSERIAL PRIMARY KEY,
    rule_name    TEXT NOT NULL,
    rule_type    TEXT NOT NULL,        -- DENY_CATEGORY | ALLOW_LIST | BLOCK_LIST | RISK_OVERRIDE
    match_target TEXT NOT NULL,        -- e.g. domain suffix, exact domain, category
    action       TEXT NOT NULL,        -- ALLOW | WARN | MONITOR | BLOCK
    priority     INT  NOT NULL DEFAULT 100,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- RESOLVE: business asset registry used for impact scoring.
-- ---------------------------------------------------------------------
CREATE TABLE asset (
    asset_id    TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    asset_type  TEXT NOT NULL,          -- WEB | API | DB | ENDPOINT | SERVICE | CLOUD
    criticality DOUBLE PRECISION NOT NULL,   -- 0..1
    sensitivity DOUBLE PRECISION NOT NULL,   -- 0..1 data sensitivity
    owner       TEXT,
    dept        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE
);

-- ---------------------------------------------------------------------
-- LORE: outcome feedback that drives weight learning.
-- ---------------------------------------------------------------------
CREATE TABLE outcome_feedback (
    feedback_id    BIGSERIAL PRIMARY KEY,
    decision_id    UUID NOT NULL REFERENCES decision_log (decision_id),
    realized_risk  DOUBLE PRECISION NOT NULL,   -- analyst/automated label 0..1
    was_correct    BOOLEAN NOT NULL,
    notes          TEXT,
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed a small policy rule set and asset registry (adjust to your estate).
INSERT INTO policy_rule (rule_name, rule_type, match_target, action, priority)
VALUES ('Block known malware domains', 'BLOCK_LIST', 'example-malware.test', 'BLOCK', 10),
       ('Block phishing category',      'DENY_CATEGORY', 'phishing', 'BLOCK', 20),
       ('Allow corporate zone',         'ALLOW_LIST', 'corp.example.com', 'ALLOW', 5);

INSERT INTO asset (asset_id, name, asset_type, criticality, sensitivity, owner, dept)
VALUES ('asset-billing', 'Billing Portal', 'WEB', 0.95, 0.90, 'finance@example.com', 'Finance'),
       ('asset-mail',    'Corporate Mail', 'API', 0.85, 0.80, 'it@example.com', 'IT'),
       ('asset-build',   'CI Build Farm', 'SERVICE', 0.60, 0.30, 'eng@example.com', 'Engineering');
