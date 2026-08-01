# FIDES — the Dynamic Trust Engine

**Full name:** **FI**nite-state **D**ecision **E**vidence **S**corer (trust
subsystem).

FIDES models *reputation* as a live, asymmetric, decaying scalar per entity —
the answer to "how much have we historically trusted this entity, and how sure
are we?" It is not a static scorecard; it is a **stateful process** driven by
every interaction.

Implemented in `trust/`:

- `FidesTrustEngine` — the engine.
- `TrustEvent` (entity, event type, strength, narrative, at),
  `TrustContext`, `TrustAssessment`, `TrustProperties`.
- Optional persistence via `TrustProfileStore` (`JdbcTrustProfileStore`).
- REST via `TrustController`.

---

## 1. The trust model

For each entity, FIDES keeps:

```
trust(T)              ∈ [0,1]   current reputation
confidence(C)         ∈ [0,1]   how sure we are of T
observationCount(N)             how many events shaped this profile
firstSeenAt, lastUpdatedAt
```

`TrustAssessment = (trust, confidence, observationCount)`.

## 2. Update rule (asymmetric)

When an event arrives with signed strength `e ∈ [−1, +1]`:

```
gain = e ≥ 0 ? positiveGain : negativeGain        (0.15 vs 0.35)

Δ = gain · (target − T)          target = 1 if e ≥ 0 else 0
T' = clamp( T + e · Δ , 0.05, 0.95 )
```

**Asymmetry is the point**: negative evidence is weighted ~2.3× heavier than
positive evidence (`0.35 / 0.15`), because reputation is hard to earn and easy
to lose — matching both human trust psychology and the observed structure of
attacker campaigns (one exfiltration event outweighs months of clean behaviour).

The update is **anchored toward 0.5** for extreme positions (the `target − T`
factor): trust is mean-reverting, so a single contradictory event does not flip
a long-established profile.

## 3. Confidence

```
confidence = 1 − exp(−N / N0)        N0 = 60 (configurable)
```

- Few observations → low confidence (don't trust the trust).
- Saturates toward 1 as history accumulates.
- Confidence gates the *influence* of the trust slice in SYNAPSE
  (`c_trust` in the log-odds sum, `docs/02-decision-algorithm.md` §2).

## 4. Decay

`TrustProperties.decayHalfLifeHours` (default 24h) applies a gradual drift back
toward 0.5 on read/refresh, so trust reflects the *present*, not a stale snapshot:

```
if lastUpdatedAt older than halfLife:
    T ← 0.5 + (T − 0.5) · exp(−hoursSinceUpdate·ln2 / halfLife)
```

Decayed profiles keep their confidence (they are still *well-measured*, just
older) — the evidence-slice freshness facet in SYNAPSE independently penalises
stale data.

## 5. Event types

Events are typed strings; the scaffold defines a set used across engines:

```
OBSERVATION_POSITIVE  (clean resolution, benign behaviour)
OBSERVATION_NEGATIVE  (malicious activity, blacklist hit)
RESOLUTION_OK         (DNS resolution behaved as expected)
RESOLUTION_SUSPICIOUS (resolution to known-bad infrastructure)
ALERT_HIGH            (high-severity alert on this entity)
```

`FidesTrustEngine.apply(event)` updates the profile and (if a store is present)
persists the event + profile.

## 6. REST + store

```
GET    /api/v1/trust/{entityId}         → TrustAssessment
POST   /api/v1/trust/event              → apply TrustEvent
```

`JdbcTrustProfileStore` persists profiles to the `trust_profile` table and
events to `trust_event` (see `docs/07-database.md`).

## 7. Worked example (from the unit tests)

A new entity starts at `T = 0.5, C = 0`.

1. `POSITIVE` event, strength 1.0 → `T = 0.50 + 0.15·(1−0.50) = 0.575`
   (`Δ = +0.15·0.5 = 0.075`), then `C = 1−e^−1/60 ≈ 0.017`.
2. Repeated positives converge upward toward 0.95 (the ceiling) at a
   decelerating rate.
3. A single `NEGATIVE` event, strength 1.0 → drops ~0.175 (0.35·0.5) — one
   bad event erases ~2.3 good ones.
4. 60+ observations → confidence ≈ 0.63; 300+ → ≈ 0.99.

## 8. Design notes

- **Separating T and C** prevents "we're confident about a bad actor" and
  "we're unsure about a good actor" from being conflated into a single number.
- **Ceiling/floor clamps** (0.05/0.95) keep logits finite
  (logit(0.05) ≈ −2.94) so the trust slice can never blow up SYNAPSE's sum.
- Trust is **per-entity, not per-source**: events from any provider feed the same
  profile, which is exactly what makes cross-provider fusion coherent.
