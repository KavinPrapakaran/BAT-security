# BAT security — Overview

> **Engineering-first, evidence-driven.**

**One-line definition:** BAT security is a novel cybersecurity *decision*
framework — a purpose-built reasoning core that sits *above* SIEM, SOAR, IDS,
and firewalls and answers a question those tools do not: **what is the most
defensible action to take right now, given every scrap of evidence we have ever
seen about this entity?**

It is not a monitoring product, not an alert generator, not a firewall policy
editor, and not a neural-network black box. It is a **modular decision engine**
that fuses heterogeneous signals — network telemetry, trust history, episodic
memory, attacker intent, consequence modelling, and learned behaviour — into a
single, calibrated, fully explainable decision with a recommended action.

---

## 1. Why BAT security?

Existing tools leave a gap:

| Concern | SIEM / IDS | SOAR | BAT security |
|---|---|---|---|
| What is happening? | Detects & alerts | Correlates incidents | — |
| Who is the actor? | Partial | Playbook lookup | **Dynamic trust + intent model** |
| What did we see before? | Raw logs | Incident tickets | **Episodic memory graph** |
| What is the impact? | Asset criticality tags | Manual | **Automated consequence scoring** |
| What should we do? | Human decides | Fixed playbooks | **Calibrated recommendation** |
| Why? | Alert text | Runbook | **Full reasoning chain** |

Alerts are cheap; decisions are hard. BAT security collapses the gap between
"something suspicious happened" and "we should do X because of A, B, C."

## 2. Core idea

Every decision target — a domain, an IP, an account, a host, a cloud resource —
is described by a vector of **evidence slices**, each produced by an *engine*:

1. **ACTG (Graph)** — the Adaptive Cognitive Trust Graph: relationship
   intelligence linking domains, IPs, devices, users, certificates, and
   incidents so first-touch entities inherit the risk of everything they touch.
2. **Observatory** — raw evidence ingestion, provenance, confidence calibration.
3. **Fides (Trust)** — how much have we *historically* trusted this entity?
4. **Mnemonic (Memory)** — what *similar* entities did we see before, and what
   happened to them?
5. **Seer (Prediction)** — given current behaviour, where is this heading?
6. **Motive (Intent)** — what is the *most likely adversarial intent*?
7. **Resolve (Impact)** — what is at stake if this entity is malicious?
8. **Profiles** — organization risk profiles: risk tolerance and org-scoped
   policy rules for hospitals, banks, universities, and more.
9. **Synapse (Decision)** — fuses all of the above into a calibrated risk score,
   a decision band (ALLOW / MONITOR / WARN / CHALLENGE / ESCALATE / ISOLATE /
   BLOCK), and a recommended action.
10. **Pact (Recommendation)** — turns the decision band into concrete, safe action
    suggestions.
11. **Lore (Learning)** — closes the loop: outcomes of past decisions adjust the
    fusion weights and behaviour baselines over time.

## 3. Signature property: explainability

Every decision carries a **reasoning chain** — an ordered list of
`(engine, claim, score, confidence)` steps:

```
1. ACTG:        evil.example resolves to 185.220.101.34; that IP carried 3 malicious domains (association risk 0.91)
2. OBSERVATORY: 24 signals aggregated; dominant DNS_DGA signal strength 0.84 (conf 0.75)
3. FIDES:       trust of evil.example = 0.28, confidence 0.77 (12 observations)
4. MNEMONIC:    salience 0.84 - 3 similar entities in memory; 2 resolved as malicious
5. SEER:        predicted risk 0.79 in 30m (logistic trend, growth 1.9x)
6. MOTIVE:      intent = EXFILTRATION (confidence 0.82)
7. RESOLVE:     business impact 0.81 on asset 'asset-billing' (WEB, criticality 0.95)
8. PROFILES:    org 'hospital' risk tolerance 0.70; hard policy BLOCK on policy rule
9. SYNAPSE:     fused risk 0.87, confidence 0.88, band BLOCK
10. PACT:        recommended action = QUARANTINE_DOMAIN
```

An operator (or an auditor) can read *why* a decision was made in seconds — no
LLM, no opaque model. The chain is machine-readable (`ReasoningStep`) and can be
persisted with each decision (`decision_log.reasoning_chain`).

## 4. Ground rules of the framework

1. **Novelty over reimplementation.** Each engine is a first-principles
   contribution, not a wrapper around an existing product.
2. **Modular by construction.** A new source of evidence (e.g. an email gateway)
   is a new *analyzer/provider* that plugs into Observatory; a new decision
   domain (e.g. identity) is a new *engine* that feeds the ACDE. No core
   redesign.
3. **Everything is a number in [0,1].** All signals, trust values, memory
   saliences, impacts, and risk scores are calibrated probabilities/severities in
   `[0,1]`, so fusion is well-defined and monotonic in each input.
4. **Explainability is not optional.** No decision is emitted without a reasoning
   chain.
5. **The framework learns, but never goes dark.** Lore adjusts weights within
   hard bounds; a human can always read the current weights and bands.
6. **Fast by default.** Every engine is O(1)–O(n) per decision in the reference
   implementation; heavy learning happens offline.

## 5. Reference implementation status

A working scaffold exists in this repository:

- Language: **Java 21**, build: **Maven**, runtime: **Spring Boot 3.5.16**.
- Storage: **H2 (in-memory, PostgreSQL mode)** for dev/test; **PostgreSQL**
  schema shipped for production.
- API: REST at `/api/v1/**` (see `docs/06-api.md`).
- Tests: 144 tests, all green (see `docs/08-testing.md`), including a full
  Spring context smoke test against H2.

Engine | Code | Tests
---|---|---
ACTG (trust graph) | `actg/SecurityKnowledgeGraph` + `ActgAnalyzer` | 8
ACDE (single decision-maker) | `acde/AcdeEngine` | +4 (org profiles)
SYNAPSE decision | `algorithm/SynapseEngine` | 6
Observatory | `observatory/*` | (via DIE)
DIE (DNS Intelligence Engine) | `dns/*` + 17 analyzers | 9
VOID (Email Intelligence Engine) | `email/*` + 8 analyzers | 19
Benchmark (calibration) | `benchmark/DecisionBenchmark` | 3
LORE (decision learning) | `learning/LoreLearningEngine` | 9
Profiles (organization) | `profile/ProfileEvaluationEngine` | 5
Mnemonic memory | `memory/MnemonicMemoryEngine` | 8
Fides trust | `trust/FidesTrustEngine` | 6
Context | `context/SituationalContextEngine` | 4
Persistence | `persistence/*` (IOC + ACTG + decision log) | 7
Spring boot wiring + H2 | `CognesisApplication` + config | 3

## 6. Terminology glossary

| Term | Meaning |
|---|---|
| Entity | Decision target (domain, IP, account, host, asset...). |
| ACTG | Adaptive Cognitive Trust Graph: relationship intelligence across entities. |
| Evidence | Any observed fact about an entity, with strength & confidence. |
| Engine | A named, independent reasoning module. |
| Decision band | ALLOW / MONITOR / WARN / CHALLENGE / ESCALATE / ISOLATE / BLOCK. |
| Risk score | Fused severity in [0,1]; the output of SYNAPSE. |
| Reasoning chain | Ordered, auditable list of engine claims. |
| Salience | Memory activation strength of an entity. |
| Trust | Dynamic reputation in [0,1] with its own confidence. |
| Baseline | Learned normal behaviour (mean ± deviation). |
| Policy | Static, human-authored rule that can short-circuit decisions. |
| Organization profile | Per-org risk tolerance + org-scoped policy rules. |

## 7. How to read the docs

```
docs/00-overview.md          <- you are here
docs/01-architecture.md      <- modules, data flows, integration points
docs/02-decision-algorithm.md<- SYNAPSE: the fusion math, bands, weights
docs/03-dns-engine.md        <- DIE: the DNS Intelligence Engine (module deep-dive)
docs/04-memory-engine.md     <- MNEMONIC: episodic memory graph + learning
docs/05-trust-engine.md      <- FIDES: trust lifecycle, formulas, decay
docs/06-api.md               <- REST contracts and example payloads
docs/07-database.md          <- schemas, seed data, migration notes
docs/08-testing.md           <- test strategy and coverage map
docs/09-roadmap.md           <- what exists, what comes next
```
