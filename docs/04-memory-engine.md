# MNEMONIC — the Episodic Memory Engine

**Full name:** **MNEMO**n**IC** knowledge engine.

MNEMONIC gives COGNESIS *episodic* memory: "have we seen something like this
before, and what happened to it?" It is a lightweight in-memory **knowledge
graph** of entities and relations, recalled via **spreading activation** — the
same retrieval metaphor used in cognitive models (Anderson's ACT-R), adapted to
cyber entities.

Implemented in `memory/`:

- `MnemonicMemoryEngine` — the engine (graph, activation, baselines).
- `MemoryIncident` (subject, verb, object, severity, when),
  `MemoryItem`, `MemoryQuery`, `MemoryRecall`.
- `MemoryEngine` (interface), REST via `MemoryController`.

---

## 1. Storage model

A graph of **nodes** (entities) and **weighted directed edges** (relations):

```
Node:  key(id)        e.g. "evil.example"
       type           "DOMAIN" | "IP" | "HASH" | "ACCOUNT" | ...
       baseWeight     severity-derived recall weight
       lastSeenAt
Edge:  from → to
       relation       "CONNECTED_TO" | "RESOLVES_TO" | "SAME_OWNER" | ...
       weight         association strength
```

`memorize(incident)` upserts the subject node and, if the incident has a target,
creates/strengthens an edge between them. Repeated observations strengthen edges
(weight = `min(1, w + gain)`), so recurring patterns surface more strongly.

## 2. Retrieval: spreading activation

`recall(query)` — "what do I remember about/around X?":

```
1  seed = find node for query.entityId (by id, or composite key fallback)
   if no seed → empty recall (aggregate salience defaults to 0.5 = neutral)

2  activation[seed] = baseWeight · exp(−t_hours / τ)     (recency decay)

3  propagate for hop in {1, 2}:
       for each node with activation a:
           for each outgoing edge (to target, weight w):
               activation[target] += a · w · propagationFactor
                                            (propagationFactor = 0.4)
       a 1-hop * 0.4 · w propagates; 2-hop decays again (bounded depth)

4  return items = activated nodes (activation > 0), ranked, with hops
```

**Why spreading activation?** Because "similar" in cyber is *relational*: a
domain that resolved to the same IP, shared a registrar, or was seeded by the
same campaign as a previously-malicious entity should surface even if the domain
itself has never been seen. Pure string-similarity would miss that.

### Salience semantics

- **Non-empty recall** → salience = mean activation of recalled items, so the
  decision engine receives "how strongly does the past echo this?"
- **Empty recall** → **0.5 (neutral)**: the absence of memory must not move the
  decision either way. This is a deliberate calibration decision
  (see `docs/02-decision-algorithm.md` §2 — neutral contributes zero).

## 3. Baseline deviation (S_D slice)

MNEMONIC also owns **behaviour baselines** for normalcy scoring — the
deviation slice `S_D` used by SYNAPSE.

- Baselines are maintained per `(entityType, key)` with **Welford's online
  algorithm** (running mean, M2, variance) — O(1) memory, no history replay.
- `deviation(entityType, key, value)` returns `0.5 + k·z` capped to [0,1]:
  values far from the learned mean flag behaviour change.

Example: the DNS engine feeds each resolution's TTL / record-count into the
domain's baseline; a sudden jump to flux-like patterns raises `S_D`.

## 4. Learning (offline)

| Learning | Mechanism |
|---|---|
| Baseline statistics | Welford mean/variance update per observation |
| Edge weights | incremental strengthen on repeat association |
| Node decay | exponential recency decay on recall (optionally persisted) |
| Outcome learning | `Outcome` records from decisions reinforce/decay related edges |

`LoreLearningEngine` (see `learning/`) additionally tunes SYNAPSE weights from
outcomes; MNEMONIC supplies the salience side.

## 5. API

```
POST /api/v1/memory/memorize   { incident }              → status
POST /api/v1/memory/recall     { entityId, entityType }  → MemoryRecall
```

## 6. Complexity

- `memorize`: O(1) (map upsert + edge upsert).
- `recall`: O(V + E) over activated subgraph, bounded to 2 hops (configurable).
- Baselines: O(1) per update.

## 7. Design notes

- **Neutral-on-empty** (0.5) is the most important calibration in this engine:
  without it, every first-seen entity would look anomalous.
- **2-hop bound** keeps recall cheap and contextually focused; infinite
  propagation would dilute activation into a noise floor.
- The graph is in-memory for the scaffold (`ConcurrentHashMap`); a production
  deployment persists nodes/edges to the `memory_node` / `memory_edge` tables
  shipped in `docs/07-database.md` and loads them warm.
