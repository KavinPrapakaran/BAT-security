# SYNAPSE — the Decision Algorithm

**Full name:** **SYN**thesized **A**ssessment of **P**robabilistic **S**ecurity
**E**vidence.

SYNAPSE is the heart of BAT security. It fuses the evidence slices produced by
the other engines into a single calibrated risk score, maps it to a decision
band, and emits a recommended action. Everything below is implemented in
`algorithm/SynapseEngine` and `math/LogitOps`.

---

## 1. Inputs

`SynapseInput` carries, for one entity at one instant:

| Slice | Symbol | Meaning | Default weight |
|---|---|---|---|
| Evidence | `S_E` | aggregated strength of current signals | `0.50` |
| Trust | `S_T` | 1 − dynamic trust (distrust) | `0.15` |
| Memory | `S_M` | salience of similar past entities | `0.08` |
| Intent | `S_I` | adversarial intent weight | `0.08` |
| Prediction | `S_P` | predicted near-future risk | `0.05` |
| Deviation | `S_D` | how far current behaviour deviates from baseline | `0.04` |
| Impact | `S_B` | business impact of the entity's assets | `0.70`* |

\* `S_B` is the **lambda** factor — see §3. Weights do **not** need to sum to 1;
they are a learned allocation, not a distribution.

Weights live in `SynapseWeights` (defaults above) and are adjustable via
`cognesis.synapse.weights.*` or by `LoreLearningEngine`.

## 2. Likelihood fusion

The six ordinary slices are fused with **log-odds (logit) weighting**, relative
to the neutral point 0.5:

```
odds(prior) = ln(0.5 / 0.5) = 0          (neutral prior, contributes nothing)

logit_sum = Σ_k  w_k · c_k · ( logit(S_k) − logit(0.5) )
            k ∈ {E, T, M, I, P, D}

L = σ( logit_sum )          σ(x) = 1/(1+e^−x)
```

where `c_k` is each slice's confidence and

```
logit(s) = ln( s / (1−s) )
```

**Properties (by construction):**

- A *neutral* slice (`S_k = 0.5`) contributes **zero** to the sum — it cannot
  move the decision.
- A slice with zero confidence contributes zero (you cannot be moved by a signal
  nobody believes).
- Fusion is *additive in log-odds*: two weak signals combine sensibly, and one
  strong signal dominates (this is the mathematical justification for the
  dominant-signal rule in Observatory).
- Result is guaranteed in `(0,1)`.

### Decisiveness of the evidence slice

`LogitOps.decisiveness(s)` measures how far a signal deviates from neutral:

```
decisiveness(s) = s·log2(s) + (1−s)·log2(1−s) + 1        (binary entropy, 0..1)
```

## 3. Risk blend with impact (the lambda factor)

Pure likelihood says "how likely is this bad?"; impact says "how bad is it if
it is?" SYNAPSE blends them with a power-law that preserves order:

```
λ = S_B
risk = L^(1−λ) · B_(edge)^λ
```

where `B_(edge)` is the boundary-neutral impact used as a conservative anchor.
With λ near 0 (low-stakes asset) the decision is dominated by likelihood; with
λ near 1 (crown-jewel asset) it is dominated by impact — mirroring how human
risk managers actually decide.

## 4. Confidence

Decision confidence is a **weighted arithmetic mean** over six quality facets
(each in [0,1]):

| Facet | Derivation |
|---|---|
| Decisiveness | mean `decisiveness(S_k)` across fused slices |
| Agreement | 1 − range of slice scores (spread penalty) |
| Coverage | fraction of fused slices present & confident |
| Freshness | decay of oldest observation, `exp(−age/τ)` |
| Provenance quality | mean provenance trustworthiness |
| Context weight | 1 − (weight of any weak/absent slice) |

```
confidence = Σ_j u_j · facet_j       u = {0.25, 0.20, 0.15, 0.15, 0.15, 0.10}
```

## 5. Decision bands

`DecisionBandPolicy` maps risk to one of **seven** bands, applying **tolerance
scaling** and a **low-confidence escalation** rule.

| Band | Default lower bound | Meaning | Example action |
|---|---|---|---|
| ALLOW | — | normal; no action | allow |
| MONITOR | `0.30` | noteworthy; keep passive watch | monitor / rate-limit |
| WARN | `0.45` | present a warning | warn + notify owner |
| CHALLENGE | `0.58` | require verification | step-up MFA |
| ESCALATE | `0.68` | hand to a human analyst | escalate / enrich |
| ISOLATE | `0.82` | contain while staying observable | quarantine asset |
| BLOCK | `0.92` | intervene now | block domain/IP |

- **Tolerance**: a per-tenant or per-asset multiplier shifts the boundaries
  (highly tolerant environments tolerate higher risk before escalating).
- **Escalate when uncertain**: if `confidence < lowConfidenceThreshold (0.25)`
  the band is promoted one step up the ladder (ALLOW→MONITOR→WARN→CHALLENGE→
  ESCALATE→ISOLATE, capped at BLOCK) — when the framework is unsure *and* risk
  is near a boundary, it errs toward caution but never silently BLOCKs without
  evidence.

## 6. Pseudocode

```
function decide(input: SynapseInput, weights: SynapseWeights, bands: DecisionBandPolicy):
    logitSum = 0
    for k in {E,T,M,I,P,D}:
        c = input.confidence(k)
        s = input.score(k)
        if c > 0 and s != 0.5:
            logitSum += weights[k] * c * (logit(s) − logit(0.5))
    likelihood = sigmoid(logitSum)

    lambda_ = input.impact
    anchor   = bands.impactAnchor   # e.g. 0.5 neutral-impact anchor
    risk     = likelihood^(1−lambda_) * anchor^lambda_

    facets = [decisiveness(avg), 1−range, coverage, freshness, provenance, context]
    confidence = Σ u_j * facet_j

    band = bands.mapRisk(risk, confidence)   # 7 bands, tolerance-scaled
    if confidence < bands.lowConfidenceThreshold:
        band = promote(band)   # one rung up the ladder, capped at BLOCK

    return SynapseDecision(risk, confidence, band, weights.used)
```

## 7. Complexity

- Fusion: **O(1)** (7 slices).
- Confidence facets: **O(k)** for k slices.
- Entire SYNAPSE decision: **O(1)** — independent of memory size or evidence
  volume at decision time (heavy work is done by engines beforehand).

## 8. Learning (Lore) hooks

`LoreLearningEngine` adjusts weights from feedback outcomes:

```
gap       = |y − 0.5|                       (how decisive the realized risk was)
direction = +1.0  CONFIRMED_MALICIOUS
            −1.0  FALSE_POSITIVE
            −0.5  CONFIRMED_BENIGN
s_avg     = mean of the signal strengths that fired (0.75 if not provided)

Δw_k      = ETA · gap · direction · s_avg       ETA = 0.02
w_k       <- clamp(w_k + Δw_k, 0, 2.0)
w_likelihood <- clamp(w_likelihood + 2·Δw_k, 0, 1)
```

A calibration offset is tracked alongside, bounded to `[−0.5, +0.5]`: repeated
false positives push it negative, missed detections push it positive, and
correct verdicts barely move it (half step). All updates are bounded and fully
readable — LORE learns but never goes dark. Baselines used by `S_D` are updated
via Welford's algorithm (mean, M2, variance) — see `docs/04-memory-engine.md`.

## 9. Design notes / why this is novel

- **Log-odds relative to 0.5** keeps neutral signals inert, avoiding the
  "everything is a little risky" drift of naive weighted averages.
- **Impact as an exponent (λ)** is unusual: most frameworks add a criticality
  bonus (linear) or multiply by a constant. The power-law formulation keeps risk
  in [0,1] and reproduces high-impact/low-likelihood decisions (rare-but-catastrophic)
  faithfully.
- **Arithmetic confidence mean** (not geometric) was chosen so a single poor
  facet (e.g. stale evidence) degrades confidence linearly, never to ~0.
- **Bands are policy, not math**: the same risk score can map to different bands
  in different tenants via tolerance scaling.
