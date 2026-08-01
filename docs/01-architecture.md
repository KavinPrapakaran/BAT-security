# COGNESIS — Architecture

## 1. Design goals

- **Software-only**, deployable as a decision core inside an existing network.
- **Decision-time fast**: target < 5 ms per decision on commodity hardware.
- **Fully explainable**: every output carries a reasoning chain.
- **Pluggable**: new evidence providers and new domain engines are drop-in.
- **Stateful but restart-safe**: memory/trust persist (or warm-up) from storage.

## 2. Module map

```
                        ┌──────────────────────────────────────────────┐
                        │                 SYNCHRONIZER                │
                        │         (pulls evidence from sensors)        │
                        └───────────────┬──────────────────────────────┘
                                        │ raw observations
                                        ▼
   ┌────────────┐   evidence   ┌───────────────────┐
   │  SENSORS   │ ────────────► │    OBSERVATORY    │
   │ (DNS, NDR, │   fragments   │  providers,       │
   │  EDR, ...) │               │  aggregation,     │
   └────────────┘               │  calibration      │
                                └───────┬───────────┘
                                        │ aggregated evidence
                                        ▼
   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │    FIDES     │  │   MNEMONIC   │  │    SEER      │  │    MOTIVE    │
   │  trust       │  │  episodic    │  │  prediction  │  │  intent      │
   │  engine      │  │  memory      │  │  engine      │  │  engine      │
   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
          │                 │                 │                 │
          └───────┬─────────┴─────────┬───────┴─────────────────┘
                  │                   │
                  ▼                   ▼
   ┌──────────────────────────┐  ┌──────────────────────┐
   │       RESOLVE            │  │      POLICY EVALUATOR │
   │   impact engine          │  │   (hard rules)        │
   └────────────┬─────────────┘  └──────────┬───────────┘
                │                           │
                └──────────┬────────────────┘
                           ▼
                 ┌──────────────────┐
                 │     SYNAPSE      │  decision band + risk score
                 │  decision engine │  (fuses all slices)
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │       PACT       │  recommended actions
                 │  recommendation  │
                 └────────┬─────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Decision + chain    │  ──► API, policy proxy, log
              └───────────────────────┘
                          │ outcomes
                          ▼
                 ┌──────────────────┐
                 │      LORE        │  weight/baseline learning
                 │  learning engine │  (offline / batched)
                 └──────────────────┘
```

## 3. Logical layers

### 3.1 Ingestion layer (Observatory)
- **Providers** (`EvidenceProvider`) fetch/stream observations.
- **EvidenceIngestor** aggregates fragments per `(entity, type, window)`:
  - weighted mean of strengths by confidence;
  - **dominant-signal rule**: a fragment with strength ≥ 0.85 *and* confidence
    ≥ 0.8 caps the aggregate so a decisive signal is never diluted.
- Every aggregate is normalised to `[0,1]` and stamped with provenance.

### 3.2 Cognitive layer (per-entity engines)
Each engine reads the same aggregated evidence and produces one **slice**:

| Engine | Slice | Produces |
|---|---|---|
| Fides | `S_trust` | Dynamic trust in [0,1] + confidence |
| Mnemonic | `S_memory` | Salience of similar past entities |
| Seer | `S_prediction` | Predicted future risk |
| Motive | `S_intent` | Most likely adversarial intent + weight |
| Resolve | `S_impact` | Business impact of the entity's assets |
| CODE | `S_dns` (DNS domain) | Module-specific evidence (15 analyzers) |

### 3.3 Decision layer (Synapse + Pact)
- `SynapseEngine` fuses slices with learned weights → risk + band.
- `PactRecommendationEngine` maps bands to concrete actions.
- Hard **policy rules** short-circuit at this layer (e.g. block-list match → BLOCK
  with risk = confidence = 1.0).

### 3.4 Learning layer (Lore)
- Adjusts Synapse weights from decision outcomes (`Outcome` records).
- Maintains behaviour baselines (Welford mean/variance) for Mnemonic deviation.
- Runs batched; weights are clamped to `[w_min, w_max]` to stay explainable.

## 4. The orchestrator

`DecisionOrchestrator.evaluate()` runs the full pipeline for any entity type:

```
evidence       → aggregated slice
fidesTrust     → trust slice        (persisted, keyed by entity id)
memorySalience → memory slice
prediction     → trend slice
intent         → intent slice
impact         → consequence slice
synapse        → fused risk + band
pact           → recommended action
chain          → 8 reasoning steps (≥ 8 in tests)
```

The DNS engine adds three extra reasoning steps (deviation, synapse, pact) for a
total chain of ≥ 10 steps when evaluating domains.

## 5. Integration points

COGNESIS exposes **three** consumption modes:

1. **REST API** (`/api/v1/**`) — for UI, SOAR, and ad-hoc queries.
2. **Decision log** (`decision_log` table) — for audit and downstream analytics.
3. **In-process library** — the same engines are plain Java classes usable from
   a resolver or proxy without Spring.

## 6. Technology choices

| Choice | Rationale |
|---|---|
| Java 21 + Spring Boot 3.5 | LTS, virtual threads, broad ecosystem |
| Maven | standard, offline-cacheable builds |
| H2 (PostgreSQL mode) / PostgreSQL | schema portability, zero-install dev |
| Spring JDBC | light, no ORM magic; SQL visible |
| JUnit 5 + Mockito | unit + context testing |

## 7. Cross-cutting concerns

- **Concurrency**: engines are stateless between calls or internally synchronised
  (`ConcurrentHashMap`); safe for request threads.
- **Config**: `CognesisProperties` binds `cognesis.*` YAML (weights, bands, trust,
  memory knobs) into typed config objects.
- **Audit**: `ExplanationBuilder` assembles human-readable rationale from the chain.
- **Observability**: Spring Actuator health/metrics are enabled by default.
