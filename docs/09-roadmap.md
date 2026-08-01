# COGNESIS — Roadmap

## 1. Done (reference scaffold, this repository)

- **SYNAPSE** decision algorithm: log-odds fusion, impact blend, confidence
  facets, decision bands, tolerance + low-confidence escalation.
- **Observatory**: evidence model, aggregation with dominant-signal rule,
  `DnsEvidenceProvider`.
- **CODE**: Cognitive DNS Engine with 15 analyzers, hard policy override,
  intent enrichment, ≥10-step reasoning chain.
- **Fides**: asymmetric, decaying, mean-reverting trust with confidence.
- **Mnemonic**: knowledge-graph episodic memory, 2-hop spreading activation,
  Welford behaviour baselines.
- **Seer / Motive / Resolve / Pact / Lore**: prediction, intent, impact,
  recommendation, and weight-learning engines.
- **REST API** (`/api/v1/decisions`, `/dns`, `/trust`, `/memory`, `/evidence`).
- **Persistence**: H2 (dev) + PostgreSQL schema, JDBC stores, decision audit log.
- **Tests**: 31 green, incl. full Spring context smoke test.
- Build: `mvn package` produces a runnable Spring Boot jar.

## 2. Next (hardening)

- **PostgreSQL integration tests** against a real instance (Testcontainers),
  switching schema init to Flyway migrations.
- **Persistence for Mnemonic graph + Seer trends** (memory_node/memory_edge
  warm-cache load/save).
- **Lore online learning loop**: consume `outcome_feedback` rows, batch-update
  Synapse weights with audit trail (before/after weights in `decision_log`).
- **Actuator/observability** hardening: decision-rate metrics, engine latency
  gauges, `reasoning_chain` serialisation benchmarks.
- **Authentication/authorisation** on the API (OAuth2 / mTLS) and API keys for
  providers.
- **Validation fuzzing** for the analyzers (long labels, Unicode edge cases,
  path-traversal in entity IDs).

## 3. Later (framework growth)

### New evidence providers (drop-in, no core changes)
- Email gateway (SPF/DKIM/DMARC verdicts → `EMAIL_REPUTATION`).
- EDR/endpoint (process/network telemetry → `ENDPOINT_TELEMETRY`).
- Cloud CSPM (misconfig findings → `CLOUD_FINDING`).
- Threat-intel feeds (IOC matches → `THREAT_INTEL`).

### New domain engines (drop-in, no core changes)
- **CORTEX — Identity engine**: evaluates accounts/IPs/sessions; consumes
  AUTH_ANOMALY, GEO, device signals; adds an auth slice to SYNAPSE.
- **ELEVATE — Cloud engine**: evaluates cloud resources/policies.
- **VOID — Email engine**: evaluates inbound message risk before delivery.
- **SENTRY — Endpoint engine**: evaluates process/host risk.

Each is a new `*Engine` + providers + analyzers plugged into the orchestrator;
SYNAPSE and the reasoning-chain format are unchanged.

### Scale & productisation
- Event-driven ingestion (Kafka) with bounded memory graph sharding.
- Distributed store (the schemas are already relational/JSONB-ready).
- Admin UI to inspect trust, memory, weights, bands, and per-decision chains.
- SOC playbook integration (SOAR outbound actions from `RecommendedAction`).

## 4. Guiding principles for all future work

1. Every new signal must map to a `[0,1]` strength with a confidence.
2. Every new engine must contribute a named slice and a reasoning step.
3. No decision may be emitted without a chain (audit invariant).
4. Learning must be bounded, visible, and reversible.
5. Additive change only: never weaken an existing decision without a
   compatibility review.
