# BAT security — Roadmap

**Version plan:** v0.1.0 scaffold ✅ · v0.2.0 Cognitive Core ✅ · v0.3.0
Persistence & Observability ✅ · v1.0.0 Stable ✅ · v1.1.0 Detection & live
intel ✅ · v1.1.1 Hardening ✅ · **v1.2.0 BAT security (branding + intelligence
expansion) ✅**.

## 1. Done

### v0.1.0 — reference scaffold
- **SYNAPSE** decision algorithm: log-odds fusion, impact blend, confidence
  facets, decision bands, tolerance + low-confidence escalation.
- **Observatory**: evidence model, aggregation with dominant-signal rule,
  `DnsEvidenceProvider`.
- **DIE**: DNS Intelligence Engine with 17 analyzers, hard policy override,
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
- **CODE refactored** to consume the ACDE (it sees, the ACDE decides). Renamed
  **DIE** in v1.2.0.
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

## 4. Done (v1.1.0 — Detection export & live threat intel)

- **Detection export**: `POST /api/v1/detections/dns` evaluates a domain and
  returns SIEM-ready artifacts — a **Sigma** rule (dns_query logsource, level
  mapped from the decision band) and a **YARA** rule embedding the domain and
  the reasoning-chain claims. Bridges BAT security verdicts to real detection
  tooling.
- **Live threat-intel ingestion**: `ThreatFeedIngestor` fetches a host-file
  style feed (abuse.ch ThreatFox/URLhaus format), flags IOCs in the DNS facts
  repository, and `POST /api/v1/feeds/refresh` triggers a refresh on demand.
  Opt-in via `cognesis.feed.enabled` + `cognesis.feed.url`; offline/unreachable
  feeds never fail startup or throw (guarded + time-boxed).
- Flagged domains flow into ACDE verdicts through `DnsEvidenceProvider`
  (`maliciousFlagCount` → `THREAT_INTEL`-style evidence).
- **Live facts, not fixtures**: `LiveDnsFactsRepository` queries real
  DNS-over-HTTPS (Cloudflare), RDAP/WHOIS (rdap.org) and certificate
  transparency (crt.sh) per domain — DNSSEC validity, registration age,
  registrar, subdomain/cert counts — with per-source timeouts, a TTL cache,
  and wholesale fallback to the in-memory seed when offline.
- **ThreatIntel analyzer (16th)**: feed flags now enter the reasoning chain as
  `DIE:THREAT_INTEL`; a single match exceeds the MOTIVE enrichment threshold.
- **DevOps**: GitHub Actions CI (Java 21, full suite + jar), multi-stage
  Dockerfile + `docker-compose.yml` (live feed + live DNS on by default).
- **78 tests green**, incl. 7 new tests (mock-HTTP live facts, fallback &
  cache behaviour, feed-IOC escalation through the ACDE).

## 5. Done (v1.1.1 — Hardening)

- **Fail-closed API security**: no default API key is committed
  (`cognesis.security.api-keys: ""`); the service starts locked and every
  protected endpoint returns 403 until a key is configured
  (`COGNESIS_SECURITY_API_KEYS`). Key comparison is constant-time
  (`MessageDigest.isEqual`); empty-key setups are logged loudly at startup.
- **Rate limiting**: sliding-window limiter (120 req/min, burst 60,
  `cognesis.security.rate-limit-*`) after authentication → `429` +
  `Retry-After: 60` per client; `/actuator/health` and `/actuator/info` exempt.
- **Persistent IOC store**: feed-flagged domains now persist in an `ioc_flag`
  table (`IocStore`/`JdbcIocStore`, Flyway `V4__ioc_flags.sql`); flag counts
  and first-seen survive restarts and scale with a real DB. In-memory variant
  keeps tests fast.
- **DoH resolver failover**: if the primary resolver fails, lookups fall over
  to a secondary (`cognesis.dns.live.doh-fallback-url`, Google); both Cloudflare
  and Google response formats are handled.
- **SSRF / request-injection hardening**: live-source domains are validated
  against a strict label grammar and URL-encoded before any outbound call;
  unsafe input is rejected with no network contact.
- **Honest fallback**: when no live source responds, the seed facts are used
  with an explicit WARN log and a `cognesis.dns.live.fallback` counter instead
  of silently masquerading as live data.
- **Scheduled feed refresh + health**: `FeedScheduler` refreshes the feed every
  `cognesis.feed.refresh-minutes` (default 60); `/actuator/health/feed` reports
  DOWN when the feed is enabled but never refreshed or stale, and surfaces the
  live IOC count. Feed metrics (`cognesis.feed.*`) and live-facts cache/fallback
  counters added.
- **Coverage gate**: JaCoCo enforces ≥ 70% line / ≥ 55% branch coverage
  (`mvn verify`); currently 80.9% line / 64.2% branch.
- **CI depth**: live-feed smoke-test job (real URLhaus feed + PostgreSQL +
  API + health checks) and a weekly Trivy HIGH/CRITICAL CVE scan
  (`security-scan.yml`) plus Dependabot.
- **96 tests green**, incl. 18 new (IOC store persistence, fail-closed posture,
  rate limiting, DoH failover, SSRF rejection, feed health).

## 6. Done (v1.2.0 — BAT security)

- **Rebranding**: COGNESIS → **BAT security**, tagline
  "Engineering-first, evidence-driven." Package/class names, `COGNESIS_*`
  environment variables and the `cognesis.*` config namespace stay unchanged
  (branding only, no breaking changes).
- **DNS Intelligence Engine (DIE)**: the Cognitive DNS Engine is renamed;
  `CognitiveDnsEngine` remains as a `@Deprecated` alias extending the new
  `DnsIntelligenceEngine` interface. Reasoning-chain claim prefixes move from
  `CODE:` to `DIE:`.
- **ACTG — Adaptive Cognitive Trust Graph** (the distinctive internal model):
  a Security Knowledge Graph (`actg/`) linking USER, DEVICE, DOMAIN,
  CERTIFICATE, IP and INCIDENT nodes via RESOLVES_TO / REQUESTED_BY /
  SOURCE_FROM / ISSUED_FOR / ASSOCIATED_WITH / TARGET_OF edges. Nodes ratchet
  to the high-water risk of their associations; edges strengthen by `+0.25` per
  repeated observation (bounded `[1.0, 3.0]`); `neighborhoodRisk` skips
  zero-risk neighbours. Domain→IP edges are recorded **before** the analyzers
  run, so a first-touch domain that resolves to a known-bad IP inherits its
  risk. `ActgAnalyzer` (17th) emits `EvidenceType.ACTG`; `DnsFacts` gained a
  `resolvedIps` field (DoH A/AAAA extracted in the live repository).
- **Decision Learning (LORE)**: feedback kinds `CONFIRMED_MALICIOUS` (+1) /
  `FALSE_POSITIVE` (−1) / `CONFIRMED_BENIGN` (−0.5) with optional signal
  strengths (default 0.75); weight update `ETA · gap · direction · s_avg`,
  weights capped at 2.0, likelihood weight clamped to [0,1]; a bounded
  calibration offset in [−0.5, +0.5] tracks systematic over/under-flagging.
  `LoreFeedbackController` accepts `classification` + `signalStrengths` and
  returns the learned calibration.
- **Organization Profiles**: `profile/` ships `OrgProfile` + `ProfileEvaluationEngine`
  with seeded hospital (tolerance 0.70 + block rule), bank (0.80 + two rules)
  and university (1.20 + allow rule) defaults; unknown orgs fall back to the
  DEFAULT profile. `PolicyRule` gained an optional `organizationId`;
  `SynapseEngine` gained `evaluate(input, weights, band)` + `bandPolicy()`; the
  ACDE applies org-scoped hard rules and scales decision bands by the org's risk
  tolerance using `DnsResolutionRequest.context.organizationId`. Schema:
  `organization_profile` table (Flyway `V5`).
- **Mid-point check: 118 tests green** (ACTG engine slice, LORE learning,
  profile evaluation, org policy through the ACDE, DIE end-to-end); **144 tests
  green** with the additions below.
- **VOID — Email engine** (second domain engine, proving drop-in ACDE reuse):
  `email/` ships `EmailFacts` + `EmailSignal` + 8 analyzers (`EmailAuthAnalyzer`
  SPF/DKIM/DMARC, `SenderDomainAgeAnalyzer`, `SpoofingAnalyzer`, `LinkAnalyzer`,
  `AttachmentAnalyzer`, `SenderReputationAnalyzer`, `ThreatIntelEmailAnalyzer`,
  `EmailPolicyAnalyzer` hard-block). `EmailIntelligenceEngine` records ACTG
  associations before sensing, converts signals to `EvidenceFragment`, and
  delegates to the ACDE with activity `email` (new evidence types
  `EMAIL_AUTH`/`EMAIL_SENDER_AGE`/`EMAIL_SPOOF`/`EMAIL_LINKS`/
  `EMAIL_ATTACHMENTS`/`EMAIL_SENDER_REP`, provenance `EMAIL_GATEWAY`, email
  intents in `MotiveIntentEngine`). `POST /api/v1/email/evaluate`. 19 new tests.
- **Calibration benchmark**: `benchmark/DecisionBenchmark` is domain-agnostic —
  Brier score, base-rate baseline Brier, 5-bin calibration error and
  separation; verified calibrated + separated on both DNS and email catalogs
  (both Brier < 0.20). 3 new tests.
- **ACTG graph persistence**: Flyway `V6` adds `actg_node` / `actg_edge`;
  `JdbcActgStore` mirrors the `JdbcIocStore` portable upsert pattern, restores
  exact edge weights and node high-water risk via the reload path on startup,
  and clears both stores. 4 new tests.

## 7. Later (framework growth)

### New evidence providers (drop-in, no core changes)
- Email gateway (SPF/DKIM/DMARC verdicts → `EMAIL_REPUTATION`).
- EDR/endpoint (process/network telemetry → `ENDPOINT_TELEMETRY`).
- Cloud CSPM (misconfig findings → `CLOUD_FINDING`).

### New domain engines (drop-in, no core changes)
- **CORTEX — Identity engine**: evaluates accounts/IPs/sessions; consumes
  AUTH_ANOMALY, GEO, device signals; adds an auth slice to SYNAPSE.
- **ELEVATE — Cloud engine**: evaluates cloud resources/policies.
- **SENTRY — Endpoint engine**: evaluates process/host risk.

Each is a new `*Engine` + providers + analyzers feeding the ACDE;
SYNAPSE and the reasoning-chain format are unchanged.

### Scale & productisation
- Event-driven ingestion (Kafka) with bounded memory graph sharding.
- Distributed store (the schemas are already relational/JSONB-ready).
- Admin UI to inspect trust, memory, weights, bands, and per-decision chains.
- SOC playbook integration (SOAR outbound actions from `RecommendedAction`).

## 8. Guiding principles for all future work

1. Every new signal must map to a `[0,1]` strength with a confidence.
2. Every new engine must contribute a named slice and a reasoning step.
3. No decision may be emitted without a chain (audit invariant).
4. Learning must be bounded, visible, and reversible.
5. Additive change only: never weaken an existing decision without a
   compatibility review.
