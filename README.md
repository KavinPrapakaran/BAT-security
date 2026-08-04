# COGNESIS

> **C**ognitive **O**bservational **G**raph-based **N**euro-symbolic **E**vidence
> **S**ynthesis **I**ntegrating **S**tatic & dynamic analysis.

**A novel cybersecurity decision framework.** COGNESIS is not another SIEM, IDS,
or firewall — it is a decision core that answers the question those tools leave
to humans: *"given all the evidence we've ever seen about this entity, what is
the most defensible action right now, and why?"*

Every verdict is **fully explainable**, every signal is a calibrated `[0,1]`
score with a confidence, and every new data source or domain engine plugs in
without touching the core.

## Repository layout

```
docs/                design docs (start with 00-overview.md)
src/main/java/com/cognesis/framework/
  algorithm/         SYNAPSE decision engine + weights + bands
  math/              LogitOps (log-odds fusion, entropy, decisiveness)
  observatory/       evidence ingestion & aggregation (dominant-signal rule)
  dns/               CODE: Cognitive DNS Engine + 16 analyzers + live facts
                     (DoH with resolver failover, RDAP/WHOIS, crt.sh) with
                     honest offline fallback and SSRF-hardened input
  trust/             FIDES: dynamic asymmetric trust engine
  memory/            MNEMONIC: episodic knowledge graph + spreading activation
  context/           CONTEXT: situational environment risk
  prediction/        SEER: near-future risk prediction
  intent/            MOTIVE: adversarial intent assessment
  impact/            RESOLVE: business impact scoring
  recommend/         PACT: recommended actions
  learning/          LORE: weight & baseline learning
  policy/            hard policy rule evaluation
  acde/              ACDE: the single decision-maker (Cognitive Core)
  persistence/       JDBC stores (decision log, trust profiles, memory graph,
                     persistent IOC flag store)
  metrics/           Micrometer counters and timers
  validation/        input validation annotations & validators
  security/          fail-closed API key filter (constant-time compare) +
                     sliding-window rate limiter
  detection/         Sigma + YARA rule export for COGNESIS verdicts
  feed/              threat-intel feed ingestion (abuse.ch, configurable),
                     scheduled refresh + health indicator
  config/            CognesisProperties + Spring wiring
  api/               REST controllers
src/main/resources/  application.yml, db/schema-h2.sql, db/migration/
src/test/java/       96 tests (unit + Spring context + H2 + validation + security
                     + rate limiting + detection + feed + live facts + IOC persistence)
```

## Requirements

- Java 21+
- Maven 3.9+ (not required to be on PATH if cached by the wrapper)

## Build & run

```bash
mvn verify        # 96 tests + JaCoCo coverage gate (70% line / 55% branch)
mvn package       # runnable Spring Boot jar
mvn spring-boot:run   # dev profile: in-memory H2, port 8080
docker compose up --build   # containerised, live feed + live DNS on by default
```

## Authentication (fail-closed)

Every `/api/v1/**` endpoint requires a valid API key in the `X-API-Key` header.
The service starts **locked**: no default key is committed. Set one before the
first request:

```bash
export COGNESIS_SECURITY_API_KEYS=your-secret-key        # comma-separated for several
```

with `mvn spring-boot:run`, or `COGNESIS_SECURITY_API_KEYS=... docker compose up --build`.
Requests without a matching key receive `403 Forbidden`; the key comparison is
constant-time. The `/actuator/health` and `/actuator/info` endpoints stay open
for orchestration probes. Protect the API further with the built-in per-client
rate limiter (`cognesis.security.rate-limit-*`, on by default: 120 req/min
burst 60, `429 Too Many Requests` when exceeded).

## Quick start (REST)

Evaluate a DNS resolution:

```bash
curl -s http://localhost:8080/api/v1/dns/evaluate \
  -H 'X-API-Key: your-secret-key' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"paypa1.com","clientId":"alice","clientIp":"10.1.1.5"}'
```

Evaluate any entity through the ACDE (the single decision-maker):

```bash
curl -s http://localhost:8080/api/v1/decisions/evaluate \
  -H 'X-API-Key: your-secret-key' \
  -H 'Content-Type: application/json' \
  -d '{"entityId":"evil.example","entityType":"DOMAIN","requestor":"soc",
       "affectedAssetIds":["asset-billing"],"activity":"dns-resolution",
       "context":{"env":"prod"}}'
```

Full API reference: `docs/06-api.md`.

Export a verdict as SIEM-ready detection content (Sigma + YARA):

```bash
curl -s http://localhost:8080/api/v1/detections/dns \
  -H 'X-API-Key: your-secret-key' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"paypa1.com","clientId":"alice","clientIp":"10.1.1.5"}'
```

Trigger a threat-intel feed refresh (abuse.ch / URLhaus host file; on by
default via `cognesis.feed.*`, ingested at startup, on demand, and on a
schedule; flagged IOCs are persisted and survive restarts):

```bash
curl -s -X POST http://localhost:8080/api/v1/feeds/refresh \
  -H 'X-API-Key: your-secret-key'
```

Live-source health is exposed at `/actuator/health/feed` (DOWN when the feed is
enabled but never refreshed or stale).

## The engines

| Engine | Role | Docs |
|---|---|---|
| **ACDE** | Adaptive Cognitive Decision Engine — the single decision-maker | `docs/01-architecture.md` |
| **SYNAPSE** | Fuses evidence slices into a calibrated risk + decision band | `docs/02-decision-algorithm.md` |
| **CODE** | Cognitive DNS Engine — 16 analyzers, feeds the ACDE | `docs/03-dns-engine.md` |
| **MNEMONIC** | Episodic memory graph, spreading activation, baselines | `docs/04-memory-engine.md` |
| **FIDES** | Asymmetric, decaying, explainable dynamic trust | `docs/05-trust-engine.md` |
| Observatory / Context / Seer / Motive / Resolve / Pact / Lore | supporting evidence & decision engines | `docs/01-architecture.md` |

## Design documentation

```
docs/00-overview.md       concept, glossary, how to read the docs
docs/01-architecture.md   modules, data flows, integration points
docs/02-decision-algorithm.md  SYNAPSE math, bands, confidence, learning
docs/03-dns-engine.md     CODE pipeline + the 16 analyzers
docs/04-memory-engine.md  MNEMONIC storage/retrieval/learning
docs/05-trust-engine.md   FIDES formulas, decay, examples
docs/06-api.md            REST contracts and example payloads
docs/07-database.md       schemas, seed data, migration notes
docs/08-testing.md        test strategy and coverage map
docs/09-roadmap.md        done / next / later
docs/10-demo.md           end-to-end demo: live sources, BLOCK verdict, SIEM export
```

## Ground rules

1. Novel by first principles, not a wrapper around existing products.
2. Modular by construction — new evidence or domains are drop-in.
3. Everything is a number in [0,1] with a confidence.
4. No decision without a reasoning chain (audit invariant).
5. Learning is bounded, visible, reversible (never a black box).
