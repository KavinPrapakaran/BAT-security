# BAT security — Database

Two schema sources ship in `src/main/resources/db/`:

- **`schema-h2.sql`** — dev/test, run by Spring Boot on the in-memory H2
  database configured with `MODE=PostgreSQL`. Mirrors the production schema.
- **Flyway migrations (`db/migration/V1..V5`)** — authoritative production DDL
  (TIMESTAMPTZ, JSONB, BIGSERIAL, pgcrypto UUIDs, indexes); applied to
  PostgreSQL under the `postgres` profile.

---

## 1. Tables

### signal_observation (Observatory)
Raw evidence fragments ingested from providers. One row per signal.

| Column | Notes |
|---|---|
| `id` | UUID (pgcrypto / H2 `UUID`) |
| `entity_id`, `entity_type` | decision target |
| `evidence_type`, `provenance` | enum-like strings |
| `strength`, `confidence` | [0,1] |
| `explanation` | human-readable |
| `observed_at`, `created_at` | TIMESTAMPTZ |
| indexes | entity, observed_at, evidence_type |

### trust_profile + trust_event (Fides)
- `trust_profile`: one row per entity (`entity_id` PK), trust + confidence +
  observation count, first/last seen.
- `trust_event`: append-only event ledger (`BIGSERIAL`, entity, event_type,
  strength, narrative, occurred_at).

### memory_node + memory_edge + behaviour_baseline (Mnemonic)
- `memory_node`: knowledge-graph nodes; unique on `(node_type, node_key)`.
- `memory_edge`: weighted directed relations; unique
  `(source_node_id, target_node_id, relation)`; cascading FKs.
- `behaviour_baseline`: Welford statistics per `(entity_id, feature_name)` —
  mean, stddev, sample count.

### decision_log (Synapse audit)
Every decision persisted with:

| Column | Notes |
|---|---|
| `decision_id` | UUID (primary key, generated in code) |
| `entity_id`, `entity_type` | |
| `decision`, `recommended_action` | band + action |
| `risk_score`, `trust_score`, `confidence_score`, `business_impact` | [0,1] |
| `rationale` | human-readable summary |
| `reasoning_chain` | **JSONB** ordered list of `ReasoningStep` |
| `decision_request` | JSONB echo of the request |
| `decided_at` | TIMESTAMPTZ |
| indexes | entity, time, decision |

`JdbcDecisionLogDao` writes the row and serialises the chain to JSONB.

### policy_rule (Policy)
Static rules consumed by `PolicyEvaluator`: rule_type
(`BLOCK_LIST`/`DENY_CATEGORY`/`ALLOW_LIST`/`RISK_OVERRIDE`), match_target,
action, priority, enabled. Highest-priority matching rule wins.

### asset (Resolve)
Business asset registry: `asset_id`, name, type (WEB/API/DB/ENDPOINT/SERVICE/
CLOUD), criticality, sensitivity, owner, dept, enabled. `ResolveImpactEngine`
averages criticality+sensitivity of the assets linked to a decision.

### outcome_feedback (Lore)
Closed-loop learning ledger: `decision_id` → `realized_risk`, `was_correct`,
`kind`, `signal_strengths`, notes. Feeds weight updates in `LoreLearningEngine`.

### organization_profile (Profiles)
Org risk profiles consumed by `ProfileEvaluationEngine`:

| Column | Notes |
|---|---|
| `organization_id` | TEXT PRIMARY KEY |
| `name` | display name |
| `risk_tolerance` | (0,2] multiplier on the decision-band thresholds |
| `enabled` | only enabled profiles apply |

Seeded (Flyway `V5__organization_profiles.sql`): `hospital` (tolerance 0.70 +
block rule), `bank` (tolerance 0.80 + two rules), `university` (tolerance 1.20 +
allow rule). Unknown orgs fall back to the DEFAULT profile (tolerance 1.0, no
rules). `policy_rule.organization_id` (nullable) scopes a rule to one org;
`InMemoryPolicyEvaluator` and the production evaluator skip org-scoped rules
when the request has no org context.

### ioc_flag (IOC store)
Persistent threat-intel flags from the feed (Flyway `V4__ioc_flags.sql`):

| Column | Notes |
|---|---|
| `domain` | TEXT PRIMARY KEY |
| `flag_count` | BIGINT, incremented each time the feed re-flags it |
| `first_seen_at`, `last_seen_at` | TIMESTAMPTZ; `first_seen_at` is immutable |

`JdbcIocStore` upserts on flag (UPDATE, else INSERT); `first_seen_at` is
preserved across reflags. Read through `IocStore` into the DNS facts
(`maliciousFlagCount`), so feed flags survive restarts and a shared DB scales
the store horizontally.

## 2. Seed data

Both schemas seed a baseline:

- 3 policy rules (block known malware domain, block phishing category,
  allow corporate zone).
- 3 assets (billing portal WEB 0.95/0.90, corporate mail API 0.85/0.80,
  CI build farm SERVICE 0.60/0.30).
- 3 organization profiles (hospital / bank / university) in the `postgres`
  profile via `V5`; the H2 schema seeds the same three idempotently.
- The H2 variant inserts idempotently (`WHERE NOT EXISTS`) so repeated context
  starts are safe.

## 3. Dev vs prod

| | Dev / test | Prod |
|---|---|---|
| Driver | H2 (`MODE=PostgreSQL`) | PostgreSQL 14+ |
| Data | ephemeral in-memory | persistent |
| Schema load | `spring.sql.init` on startup | Flyway migrations (`V1..V5`) |
| Types | TEXT / BIGINT IDENTITY / UUID | TIMESTAMPTZ / JSONB / BIGSERIAL |

To switch profiles:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=postgres
```

## 4. Migration notes

- All tables are additive; add columns with defaults, never rename PKs.
- `decision_log.reasoning_chain` JSONB is append-only (audit).
- `trust_event` and `signal_observation` grow without bound in prod — archive
  by `observed_at`/`occurred_at` (the indexes support range deletes).
- `memory_node`/`memory_edge` are the warm-cache backing for the in-memory
  graph; load on startup, persist on shutdown/batch.
