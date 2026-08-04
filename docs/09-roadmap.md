# COGNESIS — Roadmap

**Version plan:** v0.1.0 scaffold ✅ · v0.2.0 Cognitive Core ✅ · v0.3.0
Persistence & Observability ✅ · v1.0.0 Stable ✅.

## 1. Done

### v0.1.0 — reference scaffold
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
- Build: `mvn package` produces a runnable Spring Boot jar.

### v0.2.0 — Cognitive Core (ACDE)
- **ACDE** (`acde/`): the single decision-maker. All engines (DNS, and future
  Identity/Email/Endpoint/Cloud) are evidence providers; only the ACDE decides.
- **Seven decision bands**: ALLOW · MONITOR · WARN · CHALLENGE · ESCALATE ·
  ISOLATE · BLOCK, with a matching recommended-action vocabulary.
- **Canonical reasoning chain** — Evidence → Trust → Context → Intent →
  Prediction → Business Impact → Confidence/Decision → Action.
- **Context engine** (`context/`): situational environment risk and weight
  (prod vs dev, anonymised sources, activity type).
- **Cyber memory with relationships** (`memory/Relations.java`): Domain↔IP
  (RESOLVES_TO), Domain↔Certificate (HAS_CERTIFICATE), User↔Device (USED_BY),
  Attack↔Technique (USES_TECHNIQUE), Decision↔Outcome (DECIDED_ON, OUTCOME_OF).
- **Decision memory**: `recordDecision` stores every decision with its full
  reasoning path as a DECISION node; `recordOutcome` closes the loop.
- **Trust evolution**: semantic events (`TrustEvent.Events`) — certificate
  change, DNS change, suspicious behaviour, confirmed compromise — drive the
  95 → 62 → 8 style collapse of a previously-trusted entity.
- **CODE refactored** to consume the ACDE (it sees, the ACDE decides).
- **Tests**: 40 green, incl. ACDE, context, trust-evolution and decision-memory
  suites plus the Spring context smoke test.

## 2. Done (v0.3.0)

- **PostgreSQL integration tests** against a real instance (Testcontainers),
  switching schema init to Flyway migrations.
- **Persistence for Mnemonic graph + Seer trends** (memory_node/memory_edge
  warm-cache load/save) and for decision/outcome nodes.
- **Lore online learning loop**: consume `outcome_feedback` rows, batch-update
  Synapse weights with audit trail (before/after weights in `decision_log`).
- **Actuator/observability** hardening: decision-rate metrics, engine latency
  gauges, `reasoning_chain` serialisation benchmarks.
- **Validation fuzzing** for the analyzers (long labels, Unicode edge cases,
  path-traversal in entity IDs).
- **Dashboard endpoint**: `GET /api/v1/dashboard` — version, weights, JVM stats.
- **Lore feedback endpoint**: `POST /api/v1/feedback` — accept decision feedback.
- **54 tests green**, incl. validation, dashboard, lore-feedback, and DB schema.

## 3. Done (v1.0.0 — Stable)

- **API key authentication**: `X-API-Key` header or `Authorization: Bearer <key>` on
  all `/api/v1/**` and `/actuator/**` endpoints (except `/actuator/health`).
- Stateless, no sessions. Configurable keys via `cognesis.security.api-keys`.
- **62 tests green**, incl. 8 security tests (auth filter, open/closed endpoints).

## 4. Later (framework growth)

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

Each is a new `*Engine` + providers + analyzers feeding the ACDE;
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
